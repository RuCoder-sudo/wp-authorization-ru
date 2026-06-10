<?php
/**
 * Авторизация через Rambler ID (OAuth 2.0 / OpenID Connect).
 *
 * Redirect URI: https://ВАШ-САЙТ.ru/wp-json/wp-auth-ru/v1/rambler/callback
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WP_Auth_Ru_Rambler {

    const PROVIDER       = 'rambler';
    const REST_NAMESPACE = 'wp-auth-ru/v1';
    const AUTH_URL       = 'https://id.rambler.ru/authorize';
    const TOKEN_URL      = 'https://id.rambler.ru/token';
    const USERINFO_URL   = 'https://id.rambler.ru/userinfo';
    const STATE_META_KEY = 'wp_auth_ru_rambler_oauth_id';
    const NONCE_KEY      = 'wp_auth_ru_rambler_state';

    private static $instance = null;
    private $settings;

    public static function instance() {
        if ( null === self::$instance ) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        $this->settings = get_option( WP_AUTH_RU_OPTIONS_KEY, array() );
        add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );
        if ( empty( $this->settings['rambler_enabled'] ) ) return;
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
        register_rest_route( self::REST_NAMESPACE, '/rambler/start', array(
            'methods' => 'GET', 'callback' => array( $this, 'rest_start' ), 'permission_callback' => '__return_true',
        ) );
        register_rest_route( self::REST_NAMESPACE, '/rambler/callback', array(
            'methods' => 'GET', 'callback' => array( $this, 'rest_callback' ), 'permission_callback' => '__return_true',
        ) );
    }

    public static function get_callback_url() { return rest_url( self::REST_NAMESPACE . '/rambler/callback' ); }

    public static function get_start_url( $redirect_to = '' ) {
        $url = rest_url( self::REST_NAMESPACE . '/rambler/start' );
        if ( $redirect_to ) $url = add_query_arg( 'redirect_to', rawurlencode( $redirect_to ), $url );
        return $url;
    }

    public function rest_start( WP_REST_Request $request ) {
        if ( is_user_logged_in() ) { wp_safe_redirect( home_url() ); exit; }
        $state = wp_create_nonce( self::NONCE_KEY );
        set_transient( 'wp_auth_ru_rambler_state_' . $state, 1, 10 * MINUTE_IN_SECONDS );
        WP_Auth_Ru_Logger::log( 'INFO', 'rambler', 'OAuth flow начат', array( 'ip' => $_SERVER['REMOTE_ADDR'] ?? '' ) );
        $redirect_to = $request->get_param( 'redirect_to' );
        if ( $redirect_to ) set_transient( 'wp_auth_ru_rambler_redir_' . $state, esc_url_raw( urldecode( $redirect_to ) ), 10 * MINUTE_IN_SECONDS );
        wp_redirect( self::AUTH_URL . '?' . http_build_query( array(
            'client_id' => $this->settings['rambler_client_id'] ?? '', 'response_type' => 'code',
            'redirect_uri' => self::get_callback_url(), 'scope' => 'openid email profile', 'state' => $state,
        ) ) );
        exit;
    }

    public function rest_callback( WP_REST_Request $request ) {
        $error = $request->get_param( 'error' );
        if ( $error ) {
            $msg = sanitize_text_field( $error );
            WP_Auth_Ru_Logger::log( 'ERROR', 'rambler', 'Rambler вернул ошибку: ' . $msg );
            wp_safe_redirect( add_query_arg( 'rambler_oauth_error', urlencode( $msg ), wp_login_url() ) );
            exit;
        }

        $code  = sanitize_text_field( $request->get_param( 'code' )  ?? '' );
        $state = sanitize_text_field( $request->get_param( 'state' ) ?? '' );

        if ( empty( $code ) ) { $this->redirect_with_error( 'Rambler не вернул код авторизации.' ); return; }

        if ( empty( $state ) || ! get_transient( 'wp_auth_ru_rambler_state_' . $state ) ) {
            WP_Auth_Ru_Logger::log( 'WARNING', 'rambler', 'Недействительный state — возможна CSRF-атака' );
            $this->redirect_with_error( 'Недействительный state. Попробуйте снова.' );
            return;
        }
        delete_transient( 'wp_auth_ru_rambler_state_' . $state );

        $token = $this->exchange_code_for_token( $code );
        if ( is_wp_error( $token ) ) { $this->redirect_with_error( $token->get_error_message() ); return; }

        $profile = $this->get_user_profile( $token );
        if ( is_wp_error( $profile ) ) { $this->redirect_with_error( $profile->get_error_message() ); return; }

        $user_id = $this->login_or_create_user( $profile );
        if ( is_wp_error( $user_id ) ) { $this->redirect_with_error( $user_id->get_error_message() ); return; }

        wp_set_current_user( $user_id );
        wp_set_auth_cookie( $user_id, true );
        $user_obj = get_userdata( $user_id );
        if ( $user_obj ) do_action( 'wp_login', $user_obj->user_login, $user_obj );

        $redirect_to = get_transient( 'wp_auth_ru_rambler_redir_' . $state );
        delete_transient( 'wp_auth_ru_rambler_redir_' . $state );
        if ( empty( $redirect_to ) || strpos( $redirect_to, home_url() ) !== 0 ) $redirect_to = apply_filters( 'wp_auth_ru_rambler_after_login_redirect', home_url() );
        wp_safe_redirect( $redirect_to );
        exit;
    }

    private function exchange_code_for_token( $code ) {
        $response = wp_remote_post( self::TOKEN_URL, array(
            'timeout' => 20,
            'headers' => array(
                'Content-Type'  => 'application/x-www-form-urlencoded',
                'Authorization' => 'Basic ' . base64_encode( ( $this->settings['rambler_client_id'] ?? '' ) . ':' . ( $this->settings['rambler_client_secret'] ?? '' ) ),
            ),
            'body' => array( 'grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => self::get_callback_url() ),
        ) );

        if ( is_wp_error( $response ) ) {
            $msg = 'Ошибка запроса токена: ' . $response->get_error_message();
            WP_Auth_Ru_Logger::log( 'ERROR', 'rambler', $msg );
            return new WP_Error( 'rambler_token_request', $msg );
        }

        $http_code = wp_remote_retrieve_response_code( $response );
        $body      = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( ! empty( $body['error'] ) ) {
            $msg = 'Rambler: ' . ( $body['error_description'] ?? $body['error'] );
            WP_Auth_Ru_Logger::log( 'ERROR', 'rambler', $msg, array( 'http' => $http_code ) );
            return new WP_Error( 'rambler_token_error', $msg );
        }

        if ( empty( $body['access_token'] ) ) {
            $msg = 'Rambler не вернул access_token.';
            WP_Auth_Ru_Logger::log( 'ERROR', 'rambler', $msg, array( 'http' => $http_code ) );
            return new WP_Error( 'rambler_no_token', $msg );
        }

        WP_Auth_Ru_Logger::log( 'SUCCESS', 'rambler', 'Токен получен (HTTP ' . $http_code . ')' );
        return $body['access_token'];
    }

    private function get_user_profile( $access_token ) {
        $response = wp_remote_get( self::USERINFO_URL, array(
            'timeout' => 20,
            'headers' => array( 'Authorization' => 'Bearer ' . $access_token ),
        ) );

        if ( is_wp_error( $response ) ) {
            $msg = 'Ошибка запроса профиля: ' . $response->get_error_message();
            WP_Auth_Ru_Logger::log( 'ERROR', 'rambler', $msg );
            return new WP_Error( 'rambler_profile_request', $msg );
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( empty( $body ) || ! is_array( $body ) ) {
            $msg = 'Не удалось получить данные профиля от Rambler.';
            WP_Auth_Ru_Logger::log( 'ERROR', 'rambler', $msg, array( 'http' => wp_remote_retrieve_response_code( $response ) ) );
            return new WP_Error( 'rambler_profile_empty', $msg );
        }

        WP_Auth_Ru_Logger::log( 'INFO', 'rambler', 'Профиль получен: ' . WP_Auth_Ru_Logger::mask_email( $body['email'] ?? '' ) );
        return $body;
    }

    private function login_or_create_user( $profile ) {
        $rambler_id = (string) ( $profile['sub'] ?? $profile['id'] ?? '' );
        $email      = sanitize_email( $profile['email'] ?? '' );
        $first_name = sanitize_text_field( $profile['given_name']  ?? $profile['first_name']  ?? '' );
        $last_name  = sanitize_text_field( $profile['family_name'] ?? $profile['last_name']   ?? '' );
        $name       = sanitize_text_field( $profile['name'] ?? '' );
        $display    = $name ?: trim( $first_name . ' ' . $last_name ) ?: 'Rambler Пользователь';

        if ( $rambler_id ) {
            $found = get_users( array( 'meta_key' => self::STATE_META_KEY, 'meta_value' => $rambler_id, 'number' => 1, 'fields' => 'ids' ) );
            if ( ! empty( $found ) ) {
                $uid = (int) $found[0];
                wp_update_user( array( 'ID' => $uid, 'display_name' => $display, 'first_name' => $first_name, 'last_name' => $last_name ) );
                WP_Auth_Ru_Logger::log( 'SUCCESS', 'rambler', 'Вход: пользователь #' . $uid . ' (' . WP_Auth_Ru_Logger::mask_email( $email ) . ')' );
                return $uid;
            }
        }

        if ( $email ) {
            $user_by_email = get_user_by( 'email', $email );
            if ( $user_by_email ) {
                $uid = $user_by_email->ID;
                if ( $rambler_id ) update_user_meta( $uid, self::STATE_META_KEY, $rambler_id );
                wp_update_user( array( 'ID' => $uid, 'display_name' => $display, 'first_name' => $first_name, 'last_name' => $last_name ) );
                WP_Auth_Ru_Logger::log( 'SUCCESS', 'rambler', 'Вход по email: пользователь #' . $uid . ' (' . WP_Auth_Ru_Logger::mask_email( $email ) . ')' );
                return $uid;
            }
        }

        if ( empty( $email ) ) {
            $msg = 'Rambler не предоставил email пользователя.';
            WP_Auth_Ru_Logger::log( 'ERROR', 'rambler', $msg );
            return new WP_Error( 'rambler_no_email', $msg );
        }

        $username = $this->make_unique_username( strstr( $email, '@', true ) ?: $display );
        $user_id  = wp_insert_user( array(
            'user_login' => $username, 'user_email' => $email,
            'user_pass' => wp_generate_password( 24, true, true ),
            'display_name' => $display, 'first_name' => $first_name, 'last_name' => $last_name,
            'role' => get_option( 'default_role', 'subscriber' ),
        ) );

        if ( is_wp_error( $user_id ) ) {
            WP_Auth_Ru_Logger::log( 'ERROR', 'rambler', 'Ошибка создания пользователя: ' . $user_id->get_error_message() );
            return $user_id;
        }

        if ( $rambler_id ) update_user_meta( $user_id, self::STATE_META_KEY, $rambler_id );
        update_user_meta( $user_id, 'wp_auth_ru_provider', 'rambler' );
        WP_Auth_Ru_Logger::log( 'SUCCESS', 'rambler', 'Регистрация: новый пользователь #' . $user_id . ' (' . WP_Auth_Ru_Logger::mask_email( $email ) . ')' );
        return $user_id;
    }

    private function make_unique_username( $base_name ) {
        $base = sanitize_user( strtolower( str_replace( array( ' ', '-', '.' ), '_', $base_name ) ), true );
        if ( empty( $base ) ) $base = 'rambler_user';
        $username = $base; $i = 1;
        while ( username_exists( $username ) ) $username = $base . '_' . $i++;
        return $username;
    }

    public static function get_auth_start_url( $redirect_to = '' ) { return self::get_start_url( $redirect_to ); }

    private function icon() {
        return '<img src="' . esc_url( WP_AUTH_RU_PLUGIN_URL . 'assets/Image/Rambler.svg' ) . '" class="wp-auth-ru-icon" alt="Rambler" width="22" height="22" style="background:#fff;border-radius:3px;padding:1px;">';
    }

    public function render_button_wp() {
        $redirect_to = ! empty( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : '';
        ?><div class="wp-auth-ru-wrap"><a href="<?php echo esc_url( self::get_start_url( $redirect_to ) ); ?>" class="wp-auth-ru-btn wp-auth-ru-btn--rambler"><?php echo $this->icon(); ?> Войти через Rambler</a><div class="wp-auth-ru-divider"><span>или</span></div></div><?php
    }

    public function render_button_woo() {
        if ( is_user_logged_in() ) return;
        $redirect_to = ! empty( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : '';
        ?><div class="wp-auth-ru-wrap wp-auth-ru-wrap--woo"><a href="<?php echo esc_url( self::get_start_url( $redirect_to ) ); ?>" class="wp-auth-ru-btn wp-auth-ru-btn--rambler"><?php echo $this->icon(); ?> Войти через Rambler</a><div class="wp-auth-ru-divider"><span>или</span></div></div><?php
    }

    public function render_checkout_banner() {
        if ( is_user_logged_in() ) return;
        ?><div class="wp-auth-ru-checkout-banner" style="border-color:#c5d0ff;background:#f2f4ff;"><p class="wp-auth-ru-checkout-title">Войдите для оформления заказа:</p><a href="<?php echo esc_url( self::get_start_url( wc_get_checkout_url() ) ); ?>" class="wp-auth-ru-btn wp-auth-ru-btn--rambler wp-auth-ru-btn--checkout"><?php echo $this->icon(); ?> Войти через Rambler</a><p class="wp-auth-ru-hint">После входа вернётесь к оформлению заказа</p></div><?php
    }

    public function show_error( $message ) {
        if ( ! empty( $_GET['rambler_oauth_error'] ) ) {
            $err = sanitize_text_field( wp_unslash( $_GET['rambler_oauth_error'] ) );
            $message .= '<p class="message" style="color:#d63638;background:#fff3f3;padding:8px 12px;border-radius:4px;margin-top:8px;"><strong>Ошибка входа через Rambler:</strong> ' . esc_html( $err ) . '</p>';
        }
        return $message;
    }

    private function redirect_with_error( $message ) {
        WP_Auth_Ru_Logger::log( 'ERROR', 'rambler', $message );
        wp_safe_redirect( add_query_arg( 'rambler_oauth_error', urlencode( $message ), wp_login_url() ) );
        exit;
    }

    public function maybe_output_frontend_styles() {
        if ( ( function_exists( 'is_account_page' ) && is_account_page() ) || ( function_exists( 'is_checkout' ) && is_checkout() ) ) $this->output_styles();
    }

    public function output_styles() {
        static $printed = false;
        if ( $printed ) return; $printed = true;
        ?><style id="wp-auth-ru-rambler-styles">.wp-auth-ru-btn--rambler{background:#1b35ba;box-shadow:0 2px 10px rgba(27,53,186,.35)}</style><?php
    }
}
