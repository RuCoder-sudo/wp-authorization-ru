<?php
/**
 * Авторизация через ВКонтакте (VK OAuth 2.0).
 *
 * Redirect URI: https://ВАШ-САЙТ.ru/wp-json/wp-auth-ru/v1/vk/callback
 * Email возвращается прямо в ответе token endpoint (особенность VK API).
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WP_Auth_Ru_VK {

    const PROVIDER       = 'vk';
    const REST_NAMESPACE = 'wp-auth-ru/v1';
    const AUTH_URL       = 'https://oauth.vk.com/authorize';
    const TOKEN_URL      = 'https://oauth.vk.com/access_token';
    const USERS_API_URL  = 'https://api.vk.com/method/users.get';
    const API_VERSION    = '5.199';
    const STATE_META_KEY = 'wp_auth_ru_vk_oauth_id';
    const NONCE_KEY      = 'wp_auth_ru_vk_state';

    private static $instance = null;
    private $settings;

    public static function instance() {
        if ( null === self::$instance ) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        $this->settings = get_option( WP_AUTH_RU_OPTIONS_KEY, array() );
        add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );
        if ( empty( $this->settings['vk_enabled'] ) ) return;
        add_action( 'login_form',            array( $this, 'render_button_wp' ) );
        add_action( 'register_form',         array( $this, 'render_button_wp' ) );
        add_action( 'login_enqueue_scripts', array( $this, 'output_styles' ) );
        add_action( 'login_message',         array( $this, 'show_error' ) );
        if ( class_exists( 'WooCommerce' ) ) {
            add_action( 'woocommerce_login_form_start',     array( $this, 'render_button_woo' ) );
            add_action( 'woocommerce_register_form_start',  array( $this, 'render_button_woo' ) );
            add_action( 'woocommerce_before_checkout_form', array( $this, 'render_checkout_banner' ) );
        }
        add_action( 'wp_head', array( $this, 'maybe_output_frontend_styles' ) );
    }

    public function register_rest_routes() {
        register_rest_route( self::REST_NAMESPACE, '/vk/start', array(
            'methods' => 'GET', 'callback' => array( $this, 'rest_start' ), 'permission_callback' => '__return_true',
        ) );
        register_rest_route( self::REST_NAMESPACE, '/vk/callback', array(
            'methods' => 'GET', 'callback' => array( $this, 'rest_callback' ), 'permission_callback' => '__return_true',
        ) );
    }

    public static function get_callback_url() { return rest_url( self::REST_NAMESPACE . '/vk/callback' ); }

    public static function get_start_url( $redirect_to = '' ) {
        $url = rest_url( self::REST_NAMESPACE . '/vk/start' );
        if ( $redirect_to ) $url = add_query_arg( 'redirect_to', rawurlencode( $redirect_to ), $url );
        return $url;
    }

    public function rest_start( WP_REST_Request $request ) {
        if ( is_user_logged_in() ) { wp_safe_redirect( home_url() ); exit; }
        $state = wp_create_nonce( self::NONCE_KEY );
        set_transient( 'wp_auth_ru_vk_state_' . $state, 1, 10 * MINUTE_IN_SECONDS );
        WP_Auth_Ru_Logger::log( 'INFO', 'vk', 'OAuth flow начат', array( 'ip' => $_SERVER['REMOTE_ADDR'] ?? '' ) );
        $redirect_to = $request->get_param( 'redirect_to' );
        if ( $redirect_to ) set_transient( 'wp_auth_ru_vk_redir_' . $state, esc_url_raw( urldecode( $redirect_to ) ), 10 * MINUTE_IN_SECONDS );
        wp_redirect( self::AUTH_URL . '?' . http_build_query( array(
            'client_id' => $this->settings['vk_client_id'] ?? '', 'redirect_uri' => self::get_callback_url(),
            'response_type' => 'code', 'scope' => 'email', 'state' => $state, 'v' => self::API_VERSION,
        ) ) );
        exit;
    }

    public function rest_callback( WP_REST_Request $request ) {
        $error = $request->get_param( 'error' );
        if ( $error ) {
            $msg = sanitize_text_field( $error );
            WP_Auth_Ru_Logger::log( 'ERROR', 'vk', 'VK вернул ошибку: ' . $msg );
            wp_safe_redirect( add_query_arg( 'vk_oauth_error', urlencode( $msg ), wp_login_url() ) );
            exit;
        }

        $code  = sanitize_text_field( $request->get_param( 'code' )  ?? '' );
        $state = sanitize_text_field( $request->get_param( 'state' ) ?? '' );

        if ( empty( $code ) ) { $this->redirect_with_error( 'ВКонтакте не вернул код авторизации.' ); return; }

        if ( empty( $state ) || ! get_transient( 'wp_auth_ru_vk_state_' . $state ) ) {
            WP_Auth_Ru_Logger::log( 'WARNING', 'vk', 'Недействительный state — возможна CSRF-атака' );
            $this->redirect_with_error( 'Недействительный state. Попробуйте снова.' );
            return;
        }
        delete_transient( 'wp_auth_ru_vk_state_' . $state );

        $token_data = $this->exchange_code_for_token( $code );
        if ( is_wp_error( $token_data ) ) { $this->redirect_with_error( $token_data->get_error_message() ); return; }

        $profile = $this->get_user_profile( $token_data );
        if ( is_wp_error( $profile ) ) { $this->redirect_with_error( $profile->get_error_message() ); return; }

        $user_id = $this->login_or_create_user( $profile );
        if ( is_wp_error( $user_id ) ) { $this->redirect_with_error( $user_id->get_error_message() ); return; }

        wp_set_current_user( $user_id );
        wp_set_auth_cookie( $user_id, true );
        $user_obj = get_userdata( $user_id );
        if ( $user_obj ) do_action( 'wp_login', $user_obj->user_login, $user_obj );

        $redirect_to = get_transient( 'wp_auth_ru_vk_redir_' . $state );
        delete_transient( 'wp_auth_ru_vk_redir_' . $state );
        if ( empty( $redirect_to ) || strpos( $redirect_to, home_url() ) !== 0 ) $redirect_to = apply_filters( 'wp_auth_ru_vk_after_login_redirect', home_url() );
        wp_safe_redirect( $redirect_to );
        exit;
    }

    private function exchange_code_for_token( $code ) {
        $response = wp_remote_post( self::TOKEN_URL, array(
            'timeout' => 20,
            'body'    => array(
                'client_id'     => $this->settings['vk_client_id']     ?? '',
                'client_secret' => $this->settings['vk_client_secret'] ?? '',
                'redirect_uri'  => self::get_callback_url(),
                'code'          => $code,
            ),
        ) );

        if ( is_wp_error( $response ) ) {
            $msg = 'Ошибка запроса токена: ' . $response->get_error_message();
            WP_Auth_Ru_Logger::log( 'ERROR', 'vk', $msg );
            return new WP_Error( 'vk_token_request', $msg );
        }

        $http_code = wp_remote_retrieve_response_code( $response );
        $body      = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( ! empty( $body['error'] ) ) {
            $msg = 'VK: ' . ( $body['error_description'] ?? $body['error'] );
            WP_Auth_Ru_Logger::log( 'ERROR', 'vk', $msg, array( 'http' => $http_code ) );
            return new WP_Error( 'vk_token_error', $msg );
        }

        if ( empty( $body['access_token'] ) ) {
            $msg = 'VK не вернул access_token.';
            WP_Auth_Ru_Logger::log( 'ERROR', 'vk', $msg, array( 'http' => $http_code ) );
            return new WP_Error( 'vk_no_token', $msg );
        }

        WP_Auth_Ru_Logger::log( 'SUCCESS', 'vk', 'Токен получен (HTTP ' . $http_code . ', email: ' . WP_Auth_Ru_Logger::mask_email( $body['email'] ?? '' ) . ')' );
        return $body; // VK возвращает email и user_id прямо здесь
    }

    private function get_user_profile( $token_data ) {
        $response = wp_remote_get( add_query_arg( array(
            'user_ids'     => $token_data['user_id'] ?? '',
            'fields'       => 'first_name,last_name,photo_100',
            'access_token' => $token_data['access_token'],
            'v'            => self::API_VERSION,
            'lang'         => 'ru',
        ), self::USERS_API_URL ), array( 'timeout' => 20 ) );

        if ( is_wp_error( $response ) ) {
            $msg = 'Ошибка запроса профиля: ' . $response->get_error_message();
            WP_Auth_Ru_Logger::log( 'ERROR', 'vk', $msg );
            return new WP_Error( 'vk_profile_request', $msg );
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( empty( $body['response'][0] ) ) {
            $msg = 'Не удалось получить данные профиля от VK.';
            WP_Auth_Ru_Logger::log( 'ERROR', 'vk', $msg, array( 'http' => wp_remote_retrieve_response_code( $response ) ) );
            return new WP_Error( 'vk_profile_empty', $msg );
        }

        $profile              = $body['response'][0];
        $profile['email']     = $token_data['email'] ?? '';
        $profile['vk_id']     = (string) ( $token_data['user_id'] ?? $profile['id'] ?? '' );

        WP_Auth_Ru_Logger::log( 'INFO', 'vk', 'Профиль получен: vk_id=' . $profile['vk_id'] . ', email=' . WP_Auth_Ru_Logger::mask_email( $profile['email'] ) );
        return $profile;
    }

    private function login_or_create_user( $profile ) {
        $vk_id      = (string) ( $profile['vk_id'] ?? $profile['id'] ?? '' );
        $email      = sanitize_email( $profile['email'] ?? '' );
        $first_name = sanitize_text_field( $profile['first_name'] ?? '' );
        $last_name  = sanitize_text_field( $profile['last_name']  ?? '' );
        $display    = trim( $first_name . ' ' . $last_name ) ?: 'VK Пользователь';

        if ( $vk_id ) {
            $found = get_users( array( 'meta_key' => self::STATE_META_KEY, 'meta_value' => $vk_id, 'number' => 1, 'fields' => 'ids' ) );
            if ( ! empty( $found ) ) {
                $uid = (int) $found[0];
                wp_update_user( array( 'ID' => $uid, 'display_name' => $display, 'first_name' => $first_name, 'last_name' => $last_name ) );
                WP_Auth_Ru_Logger::log( 'SUCCESS', 'vk', 'Вход: пользователь #' . $uid . ' (' . WP_Auth_Ru_Logger::mask_email( $email ) . ')' );
                return $uid;
            }
        }

        if ( $email ) {
            $user_by_email = get_user_by( 'email', $email );
            if ( $user_by_email ) {
                $uid = $user_by_email->ID;
                if ( $vk_id ) update_user_meta( $uid, self::STATE_META_KEY, $vk_id );
                wp_update_user( array( 'ID' => $uid, 'display_name' => $display, 'first_name' => $first_name, 'last_name' => $last_name ) );
                WP_Auth_Ru_Logger::log( 'SUCCESS', 'vk', 'Вход по email: пользователь #' . $uid . ' (' . WP_Auth_Ru_Logger::mask_email( $email ) . ')' );
                return $uid;
            }
        }

        $username  = $this->make_unique_username( 'vk_' . ( $vk_id ?: $display ) );
        $user_args = array(
            'user_login' => $username, 'user_pass' => wp_generate_password( 24, true, true ),
            'display_name' => $display, 'first_name' => $first_name, 'last_name' => $last_name,
            'role' => get_option( 'default_role', 'subscriber' ),
        );
        if ( $email ) $user_args['user_email'] = $email;

        $user_id = wp_insert_user( $user_args );
        if ( is_wp_error( $user_id ) ) {
            WP_Auth_Ru_Logger::log( 'ERROR', 'vk', 'Ошибка создания пользователя: ' . $user_id->get_error_message() );
            return $user_id;
        }

        if ( $vk_id ) update_user_meta( $user_id, self::STATE_META_KEY, $vk_id );
        update_user_meta( $user_id, 'wp_auth_ru_provider', 'vk' );
        WP_Auth_Ru_Logger::log( 'SUCCESS', 'vk', 'Регистрация: новый пользователь #' . $user_id . ' (' . WP_Auth_Ru_Logger::mask_email( $email ) . ')' );
        return $user_id;
    }

    private function make_unique_username( $base_name ) {
        $base = sanitize_user( strtolower( str_replace( array( ' ', '-', '.' ), '_', $base_name ) ), true );
        if ( empty( $base ) ) $base = 'vk_user';
        $username = $base; $i = 1;
        while ( username_exists( $username ) ) $username = $base . '_' . $i++;
        return $username;
    }

    public static function get_auth_start_url( $redirect_to = '' ) { return self::get_start_url( $redirect_to ); }

    private function icon() {
        return '<img src="' . esc_url( WP_AUTH_RU_PLUGIN_URL . 'assets/Image/vk-svgrepo-com.svg' ) . '" class="wp-auth-ru-icon" alt="VK" width="22" height="22">';
    }

    public function render_button_wp() {
        $redirect_to = ! empty( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : '';
        ?><div class="wp-auth-ru-wrap"><a href="<?php echo esc_url( self::get_start_url( $redirect_to ) ); ?>" class="wp-auth-ru-btn wp-auth-ru-btn--vk"><?php echo $this->icon(); ?> Войти через ВКонтакте</a><div class="wp-auth-ru-divider"><span>или</span></div></div><?php
    }

    public function render_button_woo() {
        if ( is_user_logged_in() ) return;
        $redirect_to = ! empty( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : '';
        ?><div class="wp-auth-ru-wrap wp-auth-ru-wrap--woo"><a href="<?php echo esc_url( self::get_start_url( $redirect_to ) ); ?>" class="wp-auth-ru-btn wp-auth-ru-btn--vk"><?php echo $this->icon(); ?> Войти через ВКонтакте</a><div class="wp-auth-ru-divider"><span>или</span></div></div><?php
    }

    public function render_checkout_banner() {
        if ( is_user_logged_in() ) return;
        ?><div class="wp-auth-ru-checkout-banner" style="border-color:#d0dcf0;background:#f0f4ff;"><p class="wp-auth-ru-checkout-title">Войдите для оформления заказа:</p><a href="<?php echo esc_url( self::get_start_url( wc_get_checkout_url() ) ); ?>" class="wp-auth-ru-btn wp-auth-ru-btn--vk wp-auth-ru-btn--checkout"><?php echo $this->icon(); ?> Войти через ВКонтакте</a><p class="wp-auth-ru-hint">После входа вернётесь к оформлению заказа</p></div><?php
    }

    public function show_error( $message ) {
        if ( ! empty( $_GET['vk_oauth_error'] ) ) {
            $err = sanitize_text_field( wp_unslash( $_GET['vk_oauth_error'] ) );
            $message .= '<p class="message" style="color:#d63638;background:#fff3f3;padding:8px 12px;border-radius:4px;margin-top:8px;"><strong>Ошибка входа через VK:</strong> ' . esc_html( $err ) . '</p>';
        }
        return $message;
    }

    private function redirect_with_error( $message ) {
        WP_Auth_Ru_Logger::log( 'ERROR', 'vk', $message );
        wp_safe_redirect( add_query_arg( 'vk_oauth_error', urlencode( $message ), wp_login_url() ) );
        exit;
    }

    public function maybe_output_frontend_styles() {
        if ( ( function_exists( 'is_account_page' ) && is_account_page() ) || ( function_exists( 'is_checkout' ) && is_checkout() ) ) $this->output_styles();
    }

    public function output_styles() {
        static $printed = false;
        if ( $printed ) return;
        $printed = true;
        ?><style id="wp-auth-ru-vk-styles">.wp-auth-ru-btn--vk{background:#5281B8;box-shadow:0 2px 10px rgba(82,129,184,.35)}</style><?php
    }
}
