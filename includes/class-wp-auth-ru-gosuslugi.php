<?php
/**
 * Авторизация через Госуслуги (ЕСИА — Единая Система Идентификации и Аутентификации).
 *
 * ⚠️ Только для юридических лиц (ИП, ООО) с УКЭП.
 * В продуктивной среде запрос токена требует PKCS#7-подписи с УКЭП организации.
 *
 * Redirect URI: https://ВАШ-САЙТ.ru/wp-json/wp-auth-ru/v1/gosuslugi/callback
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WP_Auth_Ru_Gosuslugi {

    const PROVIDER       = 'gosuslugi';
    const REST_NAMESPACE = 'wp-auth-ru/v1';
    const AUTH_URL       = 'https://esia.gosuslugi.ru/aas/oauth2/ac';
    const TOKEN_URL      = 'https://esia.gosuslugi.ru/aas/oauth2/te';
    const PRNS_URL       = 'https://esia.gosuslugi.ru/rs/prns/';
    const AUTH_URL_TEST  = 'https://esia-portal1.test.gosuslugi.ru/aas/oauth2/ac';
    const TOKEN_URL_TEST = 'https://esia-portal1.test.gosuslugi.ru/aas/oauth2/te';
    const PRNS_URL_TEST  = 'https://esia-portal1.test.gosuslugi.ru/rs/prns/';
    const STATE_META_KEY = 'wp_auth_ru_gosuslugi_oid';
    const NONCE_KEY      = 'wp_auth_ru_gosuslugi_state';

    private static $instance = null;
    private $settings;

    public static function instance() {
        if ( null === self::$instance ) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        $this->settings = get_option( WP_AUTH_RU_OPTIONS_KEY, array() );
        add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );
        if ( empty( $this->settings['gosuslugi_enabled'] ) ) return;
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
        register_rest_route( self::REST_NAMESPACE, '/gosuslugi/start', array(
            'methods' => 'GET', 'callback' => array( $this, 'rest_start' ), 'permission_callback' => '__return_true',
        ) );
        register_rest_route( self::REST_NAMESPACE, '/gosuslugi/callback', array(
            'methods' => 'GET', 'callback' => array( $this, 'rest_callback' ), 'permission_callback' => '__return_true',
        ) );
    }

    private function is_test_mode() { return ! empty( $this->settings['gosuslugi_test_mode'] ); }
    private function get_auth_endpoint()  { return $this->is_test_mode() ? self::AUTH_URL_TEST  : self::AUTH_URL; }
    private function get_token_endpoint() { return $this->is_test_mode() ? self::TOKEN_URL_TEST : self::TOKEN_URL; }
    private function get_prns_endpoint()  { return $this->is_test_mode() ? self::PRNS_URL_TEST  : self::PRNS_URL; }

    public static function get_callback_url() { return rest_url( self::REST_NAMESPACE . '/gosuslugi/callback' ); }
    public static function get_start_url( $redirect_to = '' ) {
        $url = rest_url( self::REST_NAMESPACE . '/gosuslugi/start' );
        if ( $redirect_to ) $url = add_query_arg( 'redirect_to', rawurlencode( $redirect_to ), $url );
        return $url;
    }

    public function rest_start( WP_REST_Request $request ) {
        if ( is_user_logged_in() ) { wp_safe_redirect( home_url() ); exit; }

        $client_id = trim( $this->settings['gosuslugi_client_id'] ?? '' );
        if ( empty( $client_id ) ) {
            WP_Auth_Ru_Logger::log( 'ERROR', 'gosuslugi', 'Client ID (mnemonic) не настроен' );
            $this->redirect_with_error( 'Client ID (mnemonic) не настроен.' );
            return;
        }

        $state     = wp_create_nonce( self::NONCE_KEY );
        $timestamp = gmdate( 'Y.m.d H:i:s O' );
        set_transient( 'wp_auth_ru_gosuslugi_state_' . $state, 1, 10 * MINUTE_IN_SECONDS );
        set_transient( 'wp_auth_ru_gosuslugi_ts_' . $state, $timestamp, 10 * MINUTE_IN_SECONDS );

        $mode = $this->is_test_mode() ? 'тест' : 'продуктив';
        WP_Auth_Ru_Logger::log( 'INFO', 'gosuslugi', 'OAuth flow начат (' . $mode . ')', array( 'ip' => $_SERVER['REMOTE_ADDR'] ?? '' ) );

        $redirect_to = $request->get_param( 'redirect_to' );
        if ( $redirect_to ) set_transient( 'wp_auth_ru_gosuslugi_redir_' . $state, esc_url_raw( urldecode( $redirect_to ) ), 10 * MINUTE_IN_SECONDS );

        wp_redirect( $this->get_auth_endpoint() . '?' . http_build_query( array(
            'client_id'     => $client_id,
            'response_type' => 'code',
            'scope'         => 'openid email fullname',
            'state'         => $state,
            'redirect_uri'  => self::get_callback_url(),
            'timestamp'     => $timestamp,
            'access_type'   => 'online',
        ) ) );
        exit;
    }

    public function rest_callback( WP_REST_Request $request ) {
        $error = $request->get_param( 'error' );
        if ( $error ) {
            $desc = sanitize_text_field( $request->get_param( 'error_description' ) ?? $error );
            WP_Auth_Ru_Logger::log( 'ERROR', 'gosuslugi', 'ЕСИА вернула ошибку: ' . $desc );
            wp_safe_redirect( add_query_arg( 'gosuslugi_oauth_error', urlencode( $desc ), wp_login_url() ) );
            exit;
        }

        $code  = sanitize_text_field( $request->get_param( 'code' )  ?? '' );
        $state = sanitize_text_field( $request->get_param( 'state' ) ?? '' );

        if ( empty( $code ) ) { $this->redirect_with_error( 'Госуслуги не вернули код авторизации.' ); return; }

        if ( empty( $state ) || ! get_transient( 'wp_auth_ru_gosuslugi_state_' . $state ) ) {
            WP_Auth_Ru_Logger::log( 'WARNING', 'gosuslugi', 'Недействительный state — возможна CSRF-атака' );
            $this->redirect_with_error( 'Недействительный state. Попробуйте снова.' );
            return;
        }
        $timestamp = get_transient( 'wp_auth_ru_gosuslugi_ts_' . $state );
        delete_transient( 'wp_auth_ru_gosuslugi_state_' . $state );
        delete_transient( 'wp_auth_ru_gosuslugi_ts_' . $state );

        WP_Auth_Ru_Logger::log( 'INFO', 'gosuslugi', 'Callback получен, обмен кода на токен' );

        $token_data = $this->exchange_code_for_token( $code, $state, $timestamp );
        if ( is_wp_error( $token_data ) ) { $this->redirect_with_error( $token_data->get_error_message() ); return; }

        $profile = $this->get_user_profile( $token_data );
        if ( is_wp_error( $profile ) ) { $this->redirect_with_error( $profile->get_error_message() ); return; }

        $user_id = $this->login_or_create_user( $profile );
        if ( is_wp_error( $user_id ) ) { $this->redirect_with_error( $user_id->get_error_message() ); return; }

        wp_set_current_user( $user_id );
        wp_set_auth_cookie( $user_id, true );
        $user_obj = get_userdata( $user_id );
        if ( $user_obj ) do_action( 'wp_login', $user_obj->user_login, $user_obj );

        $redirect_to = get_transient( 'wp_auth_ru_gosuslugi_redir_' . $state );
        delete_transient( 'wp_auth_ru_gosuslugi_redir_' . $state );
        if ( empty( $redirect_to ) || strpos( $redirect_to, home_url() ) !== 0 ) $redirect_to = apply_filters( 'wp_auth_ru_gosuslugi_after_login_redirect', home_url() );
        wp_safe_redirect( $redirect_to );
        exit;
    }

    private function exchange_code_for_token( $code, $state, $timestamp ) {
        $client_id     = trim( $this->settings['gosuslugi_client_id']     ?? '' );
        $client_secret = trim( $this->settings['gosuslugi_client_secret'] ?? '' );
        $timestamp     = $timestamp ?: gmdate( 'Y.m.d H:i:s O' );

        $body = array(
            'client_id'    => $client_id,
            'code'         => $code,
            'grant_type'   => 'authorization_code',
            'redirect_uri' => self::get_callback_url(),
            'state'        => $state,
            'timestamp'    => $timestamp,
            'token_type'   => 'Bearer',
            'scope'        => 'openid email fullname',
        );
        if ( $client_secret ) $body['client_secret'] = $client_secret;

        $response = wp_remote_post( $this->get_token_endpoint(), array(
            'timeout' => 20,
            'headers' => array( 'Content-Type' => 'application/x-www-form-urlencoded' ),
            'body'    => $body,
        ) );

        if ( is_wp_error( $response ) ) {
            $msg = 'Ошибка запроса токена: ' . $response->get_error_message();
            WP_Auth_Ru_Logger::log( 'ERROR', 'gosuslugi', $msg );
            return new WP_Error( 'gosuslugi_token_request', $msg );
        }

        $http_code = wp_remote_retrieve_response_code( $response );
        $body_arr  = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( ! empty( $body_arr['error'] ) ) {
            $msg = 'ЕСИА: ' . ( $body_arr['error_description'] ?? $body_arr['error'] );
            WP_Auth_Ru_Logger::log( 'ERROR', 'gosuslugi', $msg, array( 'http' => $http_code ) );
            return new WP_Error( 'gosuslugi_token_error', $msg );
        }

        if ( empty( $body_arr['access_token'] ) ) {
            $msg = 'ЕСИА не вернула access_token. HTTP: ' . $http_code;
            WP_Auth_Ru_Logger::log( 'ERROR', 'gosuslugi', $msg, array( 'http' => $http_code, 'body' => wp_remote_retrieve_body( $response ) ) );
            return new WP_Error( 'gosuslugi_no_token', $msg );
        }

        WP_Auth_Ru_Logger::log( 'SUCCESS', 'gosuslugi', 'Токен получен (HTTP ' . $http_code . ')' );
        return $body_arr;
    }

    private function get_user_profile( $token_data ) {
        $access_token = $token_data['access_token'];
        $parts = explode( '.', $access_token );
        if ( count( $parts ) < 2 ) {
            $msg = 'Не удалось разобрать JWT access_token.';
            WP_Auth_Ru_Logger::log( 'ERROR', 'gosuslugi', $msg );
            return new WP_Error( 'gosuslugi_jwt_parse', $msg );
        }

        $payload = json_decode( base64_decode( str_pad( strtr( $parts[1], '-_', '+/' ),
            strlen( $parts[1] ) % 4 ? strlen( $parts[1] ) + 4 - strlen( $parts[1] ) % 4 : 0, '=' ) ), true );
        $oid = $payload['urn:esia:sbj_id'] ?? $payload['sub'] ?? '';

        if ( empty( $oid ) ) {
            $msg = 'ЕСИА не вернула OID пользователя.';
            WP_Auth_Ru_Logger::log( 'ERROR', 'gosuslugi', $msg );
            return new WP_Error( 'gosuslugi_no_oid', $msg );
        }

        WP_Auth_Ru_Logger::log( 'INFO', 'gosuslugi', 'OID получен из JWT: ' . $oid . ', запрашиваем профиль' );

        $response = wp_remote_get( $this->get_prns_endpoint() . $oid, array(
            'timeout' => 20,
            'headers' => array( 'Authorization' => 'Bearer ' . $access_token ),
        ) );

        if ( is_wp_error( $response ) ) {
            $msg = 'Ошибка запроса профиля: ' . $response->get_error_message();
            WP_Auth_Ru_Logger::log( 'ERROR', 'gosuslugi', $msg );
            return new WP_Error( 'gosuslugi_profile_request', $msg );
        }

        $http_code = wp_remote_retrieve_response_code( $response );
        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( empty( $body ) || ! is_array( $body ) ) {
            $msg = 'ЕСИА не вернула данные профиля. HTTP: ' . $http_code;
            WP_Auth_Ru_Logger::log( 'ERROR', 'gosuslugi', $msg );
            return new WP_Error( 'gosuslugi_profile_empty', $msg );
        }

        $body['oid']          = $oid;
        $body['access_token'] = $access_token;

        WP_Auth_Ru_Logger::log( 'INFO', 'gosuslugi', 'Профиль получен: ' . WP_Auth_Ru_Logger::mask_email( $body['email'] ?? '' ) . ', OID=' . $oid );
        return $body;
    }

    private function login_or_create_user( $profile ) {
        $oid        = (string) ( $profile['oid'] ?? '' );
        $email      = sanitize_email( $profile['email'] ?? '' );
        $first_name = sanitize_text_field( $profile['firstName'] ?? $profile['first_name'] ?? '' );
        $last_name  = sanitize_text_field( $profile['lastName']  ?? $profile['last_name']  ?? '' );
        $patronymic = sanitize_text_field( $profile['middleName'] ?? '' );
        $display    = trim( $last_name . ' ' . $first_name . ' ' . $patronymic ) ?: 'Пользователь Госуслуг';

        if ( $oid ) {
            $found = get_users( array( 'meta_key' => self::STATE_META_KEY, 'meta_value' => $oid, 'number' => 1, 'fields' => 'ids' ) );
            if ( ! empty( $found ) ) {
                $uid = (int) $found[0];
                wp_update_user( array( 'ID' => $uid, 'display_name' => $display, 'first_name' => $first_name, 'last_name' => $last_name ) );
                WP_Auth_Ru_Logger::log( 'SUCCESS', 'gosuslugi', 'Вход: пользователь #' . $uid . ' (' . WP_Auth_Ru_Logger::mask_email( $email ) . ')' );
                return $uid;
            }
        }

        if ( $email ) {
            $user_by_email = get_user_by( 'email', $email );
            if ( $user_by_email ) {
                $uid = $user_by_email->ID;
                if ( $oid ) update_user_meta( $uid, self::STATE_META_KEY, $oid );
                wp_update_user( array( 'ID' => $uid, 'display_name' => $display, 'first_name' => $first_name, 'last_name' => $last_name ) );
                WP_Auth_Ru_Logger::log( 'SUCCESS', 'gosuslugi', 'Вход по email: пользователь #' . $uid . ' (' . WP_Auth_Ru_Logger::mask_email( $email ) . ')' );
                return $uid;
            }
        }

        $username  = $this->make_unique_username( 'gosuslugi_' . ( $oid ?: $first_name ) );
        $user_args = array(
            'user_login'   => $username,
            'user_pass'    => wp_generate_password( 24, true, true ),
            'display_name' => $display,
            'first_name'   => $first_name,
            'last_name'    => $last_name,
            'role'         => get_option( 'default_role', 'subscriber' ),
        );
        if ( $email ) $user_args['user_email'] = $email;

        $user_id = wp_insert_user( $user_args );
        if ( is_wp_error( $user_id ) ) {
            WP_Auth_Ru_Logger::log( 'ERROR', 'gosuslugi', 'Ошибка создания пользователя: ' . $user_id->get_error_message() );
            return $user_id;
        }

        if ( $oid ) update_user_meta( $user_id, self::STATE_META_KEY, $oid );
        if ( $patronymic ) update_user_meta( $user_id, 'gosuslugi_patronymic', $patronymic );
        update_user_meta( $user_id, 'wp_auth_ru_provider', 'gosuslugi' );
        WP_Auth_Ru_Logger::log( 'SUCCESS', 'gosuslugi', 'Регистрация: новый пользователь #' . $user_id . ' (' . WP_Auth_Ru_Logger::mask_email( $email ) . ')' );
        return $user_id;
    }

    private function make_unique_username( $base_name ) {
        $base = sanitize_user( strtolower( str_replace( array( ' ', '-', '.' ), '_', $base_name ) ), true );
        if ( empty( $base ) ) $base = 'gosuslugi_user';
        $username = $base; $i = 1;
        while ( username_exists( $username ) ) $username = $base . '_' . $i++;
        return $username;
    }

    public static function get_auth_start_url( $redirect_to = '' ) { return self::get_start_url( $redirect_to ); }

    private function icon() {
        return '<img src="' . esc_url( WP_AUTH_RU_PLUGIN_URL . 'assets/Image/gosusligi-logo.svg' ) . '" class="wp-auth-ru-icon" alt="Госуслуги" width="22" height="22" style="background:#fff;border-radius:3px;padding:1px;">';
    }

    public function render_button_wp() {
        $redirect_to = ! empty( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : '';
        ?><div class="wp-auth-ru-wrap"><a href="<?php echo esc_url( self::get_start_url( $redirect_to ) ); ?>" class="wp-auth-ru-btn wp-auth-ru-btn--gosuslugi"><?php echo $this->icon(); ?> Войти через Госуслуги</a><div class="wp-auth-ru-divider"><span>или</span></div></div><?php
    }

    public function render_button_woo() {
        if ( is_user_logged_in() ) return;
        $redirect_to = ! empty( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : '';
        ?><div class="wp-auth-ru-wrap wp-auth-ru-wrap--woo"><a href="<?php echo esc_url( self::get_start_url( $redirect_to ) ); ?>" class="wp-auth-ru-btn wp-auth-ru-btn--gosuslugi"><?php echo $this->icon(); ?> Войти через Госуслуги</a><div class="wp-auth-ru-divider"><span>или</span></div></div><?php
    }

    public function render_checkout_banner() {
        if ( is_user_logged_in() ) return;
        ?><div class="wp-auth-ru-checkout-banner" style="border-color:#bad0ef;background:#f0f5fb;"><p class="wp-auth-ru-checkout-title">Войдите для оформления заказа:</p><a href="<?php echo esc_url( self::get_start_url( wc_get_checkout_url() ) ); ?>" class="wp-auth-ru-btn wp-auth-ru-btn--gosuslugi wp-auth-ru-btn--checkout"><?php echo $this->icon(); ?> Войти через Госуслуги</a><p class="wp-auth-ru-hint">После входа вернётесь к оформлению заказа</p></div><?php
    }

    public function show_error( $message ) {
        if ( ! empty( $_GET['gosuslugi_oauth_error'] ) ) {
            $err = sanitize_text_field( wp_unslash( $_GET['gosuslugi_oauth_error'] ) );
            $message .= '<p class="message" style="color:#d63638;background:#fff3f3;padding:8px 12px;border-radius:4px;margin-top:8px;"><strong>Ошибка входа через Госуслуги:</strong> ' . esc_html( $err ) . '</p>';
        }
        return $message;
    }

    private function redirect_with_error( $message ) {
        WP_Auth_Ru_Logger::log( 'ERROR', 'gosuslugi', $message );
        wp_safe_redirect( add_query_arg( 'gosuslugi_oauth_error', urlencode( $message ), wp_login_url() ) );
        exit;
    }

    public function maybe_output_frontend_styles() {
        if ( ( function_exists( 'is_account_page' ) && is_account_page() ) || ( function_exists( 'is_checkout' ) && is_checkout() ) ) $this->output_styles();
    }

    public function output_styles() {
        static $printed = false;
        if ( $printed ) return; $printed = true;
        ?><style id="wp-auth-ru-gosuslugi-styles">.wp-auth-ru-btn--gosuslugi{background:#1466AC;box-shadow:0 2px 10px rgba(20,102,172,.35)}</style><?php
    }
}
