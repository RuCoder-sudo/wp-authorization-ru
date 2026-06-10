<?php
/**
 * Авторизация через Mail.ru OAuth 2.0.
 *
 * Redirect URI: https://ВАШ-САЙТ.ru/wp-json/wp-auth-ru/v1/mailru/callback
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WP_Auth_Ru_Mailru {

    const PROVIDER       = 'mailru';
    const REST_NAMESPACE = 'wp-auth-ru/v1';
    const AUTH_URL       = 'https://oauth.mail.ru/login';
    const TOKEN_URL      = 'https://oauth.mail.ru/token';
    const USERINFO_URL   = 'https://oauth.mail.ru/userinfo';
    const STATE_META_KEY = 'wp_auth_ru_mailru_oauth_id';
    const NONCE_KEY      = 'wp_auth_ru_mailru_state';

    private static $instance = null;
    private $settings;

    public static function instance() {
        if ( null === self::$instance ) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        $this->settings = get_option( WP_AUTH_RU_OPTIONS_KEY, array() );
        add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );
        if ( empty( $this->settings['mailru_enabled'] ) ) return;
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
        register_rest_route( self::REST_NAMESPACE, '/mailru/start', array(
            'methods' => 'GET', 'callback' => array( $this, 'rest_start' ), 'permission_callback' => '__return_true',
        ) );
        register_rest_route( self::REST_NAMESPACE, '/mailru/callback', array(
            'methods' => 'GET', 'callback' => array( $this, 'rest_callback' ), 'permission_callback' => '__return_true',
        ) );
    }

    public static function get_callback_url() { return rest_url( self::REST_NAMESPACE . '/mailru/callback' ); }

    public static function get_start_url( $redirect_to = '' ) {
        $url = rest_url( self::REST_NAMESPACE . '/mailru/start' );
        if ( $redirect_to ) $url = add_query_arg( 'redirect_to', rawurlencode( $redirect_to ), $url );
        return $url;
    }

    public function rest_start( WP_REST_Request $request ) {
        if ( is_user_logged_in() ) { wp_safe_redirect( home_url() ); exit; }
        $state = wp_create_nonce( self::NONCE_KEY );
        set_transient( 'wp_auth_ru_mailru_state_' . $state, 1, 10 * MINUTE_IN_SECONDS );
        WP_Auth_Ru_Logger::log( 'INFO', 'mailru', 'OAuth flow начат', array( 'ip' => $_SERVER['REMOTE_ADDR'] ?? '' ) );
        $redirect_to = $request->get_param( 'redirect_to' );
        if ( $redirect_to ) set_transient( 'wp_auth_ru_mailru_redir_' . $state, esc_url_raw( urldecode( $redirect_to ) ), 10 * MINUTE_IN_SECONDS );
        wp_redirect( self::AUTH_URL . '?' . http_build_query( array(
            'client_id' => $this->settings['mailru_client_id'] ?? '', 'response_type' => 'code',
            'redirect_uri' => self::get_callback_url(), 'scope' => 'userinfo', 'state' => $state,
        ) ) );
        exit;
    }

    public function rest_callback( WP_REST_Request $request ) {
        $error = $request->get_param( 'error' );
        if ( $error ) {
            $msg = sanitize_text_field( $error );
            WP_Auth_Ru_Logger::log( 'ERROR', 'mailru', 'Mail.ru вернул ошибку: ' . $msg );
            wp_safe_redirect( add_query_arg( 'mailru_oauth_error', urlencode( $msg ), wp_login_url() ) );
            exit;
        }

        $code  = sanitize_text_field( $request->get_param( 'code' )  ?? '' );
        $state = sanitize_text_field( $request->get_param( 'state' ) ?? '' );

        if ( empty( $code ) ) { $this->redirect_with_error( 'Mail.ru не вернул код авторизации.' ); return; }

        if ( empty( $state ) || ! get_transient( 'wp_auth_ru_mailru_state_' . $state ) ) {
            WP_Auth_Ru_Logger::log( 'WARNING', 'mailru', 'Недействительный state — возможна CSRF-атака' );
            $this->redirect_with_error( 'Недействительный state. Попробуйте снова.' );
            return;
        }
        delete_transient( 'wp_auth_ru_mailru_state_' . $state );

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

        $redirect_to = get_transient( 'wp_auth_ru_mailru_redir_' . $state );
        delete_transient( 'wp_auth_ru_mailru_redir_' . $state );
        if ( empty( $redirect_to ) || strpos( $redirect_to, home_url() ) !== 0 ) {
            $redirect_to = apply_filters( 'wp_auth_ru_mailru_after_login_redirect', home_url() );
        }
        wp_safe_redirect( $redirect_to );
        exit;
    }

    private function exchange_code_for_token( $code ) {
        $response = wp_remote_post( self::TOKEN_URL, array(
            'timeout' => 20,
            'headers' => array( 'Content-Type' => 'application/x-www-form-urlencoded' ),
            'body'    => array(
                'client_id'     => $this->settings['mailru_client_id']     ?? '',
                'client_secret' => $this->settings['mailru_client_secret'] ?? '',
                'grant_type'    => 'authorization_code',
                'code'          => $code,
                'redirect_uri'  => self::get_callback_url(),
            ),
        ) );

        if ( is_wp_error( $response ) ) {
            $msg = 'Ошибка запроса токена: ' . $response->get_error_message();
            WP_Auth_Ru_Logger::log( 'ERROR', 'mailru', $msg );
            return new WP_Error( 'mailru_token_request', $msg );
        }

        $http_code = wp_remote_retrieve_response_code( $response );
        $body      = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( ! empty( $body['error'] ) ) {
            $msg = 'Mail.ru: ' . ( $body['error_description'] ?? $body['error'] );
            WP_Auth_Ru_Logger::log( 'ERROR', 'mailru', $msg, array( 'http' => $http_code ) );
            return new WP_Error( 'mailru_token_error', $msg );
        }

        if ( empty( $body['access_token'] ) ) {
            $msg = 'Mail.ru не вернул access_token.';
            WP_Auth_Ru_Logger::log( 'ERROR', 'mailru', $msg, array( 'http' => $http_code ) );
            return new WP_Error( 'mailru_no_token', $msg );
        }

        WP_Auth_Ru_Logger::log( 'SUCCESS', 'mailru', 'Токен получен (HTTP ' . $http_code . ')' );
        return $body['access_token'];
    }

    private function get_user_profile( $access_token ) {
        $response = wp_remote_get(
            add_query_arg( 'access_token', $access_token, self::USERINFO_URL ),
            array( 'timeout' => 20, 'headers' => array( 'Authorization' => 'Bearer ' . $access_token ) )
        );

        if ( is_wp_error( $response ) ) {
            $msg = 'Ошибка запроса профиля: ' . $response->get_error_message();
            WP_Auth_Ru_Logger::log( 'ERROR', 'mailru', $msg );
            return new WP_Error( 'mailru_profile_request', $msg );
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( empty( $body ) || ! is_array( $body ) ) {
            $msg = 'Не удалось получить данные профиля от Mail.ru.';
            WP_Auth_Ru_Logger::log( 'ERROR', 'mailru', $msg, array( 'http' => wp_remote_retrieve_response_code( $response ) ) );
            return new WP_Error( 'mailru_profile_empty', $msg );
        }

        WP_Auth_Ru_Logger::log( 'INFO', 'mailru', 'Профиль получен: ' . WP_Auth_Ru_Logger::mask_email( $body['email'] ?? '' ) );
        return $body;
    }

    private function login_or_create_user( $profile ) {
        $mailru_id  = (string) ( $profile['id'] ?? $profile['sub'] ?? '' );
        $email      = sanitize_email( $profile['email'] ?? '' );
        $first_name = sanitize_text_field( $profile['first_name'] ?? '' );
        $last_name  = sanitize_text_field( $profile['last_name']  ?? '' );
        $name       = sanitize_text_field( $profile['name']       ?? '' );
        $display    = $name ?: trim( $first_name . ' ' . $last_name ) ?: 'Mail.ru Пользователь';

        if ( $mailru_id ) {
            $found = get_users( array( 'meta_key' => self::STATE_META_KEY, 'meta_value' => $mailru_id, 'number' => 1, 'fields' => 'ids' ) );
            if ( ! empty( $found ) ) {
                $uid = (int) $found[0];
                wp_update_user( array( 'ID' => $uid, 'display_name' => $display, 'first_name' => $first_name, 'last_name' => $last_name ) );
                if ( $email ) { $ex = get_userdata( $uid ); if ( $ex && $ex->user_email !== $email && ! email_exists( $email ) ) wp_update_user( array( 'ID' => $uid, 'user_email' => $email ) ); }
                WP_Auth_Ru_Logger::log( 'SUCCESS', 'mailru', 'Вход: пользователь #' . $uid . ' (' . WP_Auth_Ru_Logger::mask_email( $email ) . ')' );
                return $uid;
            }
        }

        if ( $email ) {
            $user_by_email = get_user_by( 'email', $email );
            if ( $user_by_email ) {
                $uid = $user_by_email->ID;
                if ( $mailru_id ) update_user_meta( $uid, self::STATE_META_KEY, $mailru_id );
                wp_update_user( array( 'ID' => $uid, 'display_name' => $display, 'first_name' => $first_name, 'last_name' => $last_name ) );
                WP_Auth_Ru_Logger::log( 'SUCCESS', 'mailru', 'Вход по email: пользователь #' . $uid . ' (' . WP_Auth_Ru_Logger::mask_email( $email ) . ')' );
                return $uid;
            }
        }

        if ( empty( $email ) ) {
            $msg = 'Mail.ru не предоставил email пользователя.';
            WP_Auth_Ru_Logger::log( 'ERROR', 'mailru', $msg );
            return new WP_Error( 'mailru_no_email', $msg );
        }

        $username = $this->make_unique_username( strstr( $email, '@', true ) ?: $display );
        $user_id  = wp_insert_user( array(
            'user_login' => $username, 'user_email' => $email,
            'user_pass' => wp_generate_password( 24, true, true ),
            'display_name' => $display, 'first_name' => $first_name, 'last_name' => $last_name,
            'role' => get_option( 'default_role', 'subscriber' ),
        ) );

        if ( is_wp_error( $user_id ) ) {
            WP_Auth_Ru_Logger::log( 'ERROR', 'mailru', 'Ошибка создания пользователя: ' . $user_id->get_error_message() );
            return $user_id;
        }

        if ( $mailru_id ) update_user_meta( $user_id, self::STATE_META_KEY, $mailru_id );
        update_user_meta( $user_id, 'wp_auth_ru_provider', 'mailru' );
        WP_Auth_Ru_Logger::log( 'SUCCESS', 'mailru', 'Регистрация: новый пользователь #' . $user_id . ' (' . WP_Auth_Ru_Logger::mask_email( $email ) . ')' );
        return $user_id;
    }

    private function make_unique_username( $base_name ) {
        $base = sanitize_user( strtolower( str_replace( array( ' ', '-', '.' ), '_', $base_name ) ), true );
        if ( empty( $base ) ) $base = 'mailru_user';
        $username = $base; $i = 1;
        while ( username_exists( $username ) ) $username = $base . '_' . $i++;
        return $username;
    }

    public static function get_auth_start_url( $redirect_to = '' ) { return self::get_start_url( $redirect_to ); }

    public function render_button_wp() {
        $redirect_to = ! empty( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : '';
        ?><div class="wp-auth-ru-wrap"><a href="<?php echo esc_url( self::get_start_url( $redirect_to ) ); ?>" class="wp-auth-ru-btn wp-auth-ru-btn--mailru"><?php echo $this->mailru_icon(); ?> Войти через Mail.ru</a><div class="wp-auth-ru-divider"><span>или</span></div></div><?php
    }

    public function render_button_woo() {
        if ( is_user_logged_in() ) return;
        $redirect_to = ! empty( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : '';
        ?><div class="wp-auth-ru-wrap wp-auth-ru-wrap--woo"><a href="<?php echo esc_url( self::get_start_url( $redirect_to ) ); ?>" class="wp-auth-ru-btn wp-auth-ru-btn--mailru"><?php echo $this->mailru_icon(); ?> Войти через Mail.ru</a><div class="wp-auth-ru-divider"><span>или</span></div></div><?php
    }

    public function render_checkout_banner() {
        if ( is_user_logged_in() ) return;
        ?><div class="wp-auth-ru-checkout-banner" style="border-color:#c0d4ff;background:#f0f4ff;"><p class="wp-auth-ru-checkout-title">Быстрый вход перед оформлением:</p><a href="<?php echo esc_url( self::get_start_url( wc_get_checkout_url() ) ); ?>" class="wp-auth-ru-btn wp-auth-ru-btn--mailru wp-auth-ru-btn--checkout"><?php echo $this->mailru_icon(); ?> Войти через Mail.ru</a><p class="wp-auth-ru-hint">После входа вернётесь к оформлению заказа</p></div><?php
    }

    private function mailru_icon() {
        return '<svg class="wp-auth-ru-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="24" height="24" rx="12" fill="#005FF9"/><rect x="5" y="8" width="14" height="9" rx="1.5" stroke="white" stroke-width="1.3" fill="none"/><path d="M5 9.5L12 14L19 9.5" stroke="white" stroke-width="1.3" fill="none"/></svg>';
    }

    public function show_error( $message ) {
        if ( ! empty( $_GET['mailru_oauth_error'] ) ) {
            $err = sanitize_text_field( wp_unslash( $_GET['mailru_oauth_error'] ) );
            $message .= '<p class="message" style="color:#d63638;background:#fff3f3;padding:8px 12px;border-radius:4px;margin-top:8px;"><strong>Ошибка входа через Mail.ru:</strong> ' . esc_html( $err ) . '</p>';
        }
        return $message;
    }

    private function redirect_with_error( $message ) {
        WP_Auth_Ru_Logger::log( 'ERROR', 'mailru', $message );
        wp_safe_redirect( add_query_arg( 'mailru_oauth_error', urlencode( $message ), wp_login_url() ) );
        exit;
    }

    public function maybe_output_frontend_styles() {
        if ( ( function_exists( 'is_account_page' ) && is_account_page() ) || ( function_exists( 'is_checkout' ) && is_checkout() ) ) $this->output_styles();
    }

    public function output_styles() {
        static $printed = false;
        if ( $printed ) return;
        $printed = true;
        $opts = get_option( WP_AUTH_RU_OPTIONS_KEY, array() );
        if ( ! empty( $opts['yandex_enabled'] ) ) return; // Яндекс уже вывел общие стили
        ?><style id="wp-auth-ru-styles">.wp-auth-ru-wrap{margin-bottom:20px}.wp-auth-ru-wrap--woo{margin-bottom:24px}.wp-auth-ru-btn{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;padding:12px 20px;border-radius:10px;text-decoration:none!important;font-size:15px;font-weight:600;line-height:1;box-sizing:border-box;cursor:pointer;border:none;transition:opacity .18s,transform .1s;color:#fff!important;margin-bottom:10px}.wp-auth-ru-btn:hover{opacity:.88;transform:translateY(-1px);color:#fff!important}.wp-auth-ru-btn:active{transform:translateY(0)}.wp-auth-ru-btn--mailru{background:#005FF9;box-shadow:0 2px 10px rgba(0,95,249,.3)}.wp-auth-ru-icon{width:22px;height:22px;flex-shrink:0;display:block}.wp-auth-ru-divider{position:relative;text-align:center;margin:4px 0 14px;color:#aaa;font-size:13px}.wp-auth-ru-divider::before{content:"";position:absolute;top:50%;left:0;right:0;border-top:1px solid #ddd}.wp-auth-ru-divider span{position:relative;background:#fff;padding:0 12px}</style><?php
    }
}
