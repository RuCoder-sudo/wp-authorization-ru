<?php
/**
 * Авторизация через мессенджер MAX (max.ru) — Mini App HMAC-SHA256.
 *
 * MAX не поддерживает стандартный OAuth 2.0.
 * Авторизация через initData + HMAC-SHA256 (аналогично Telegram Web App).
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WP_Auth_Ru_Max {

    const PROVIDER        = 'max';
    const REST_NAMESPACE  = 'wp-auth-ru/v1';
    const NONCE_ACTION    = 'wp_auth_ru_max_nonce';
    const STATE_META_KEY  = 'wp_auth_ru_max_oauth_id';

    private static $instance = null;
    private $settings;

    public static function instance() {
        if ( null === self::$instance ) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        $this->settings = get_option( WP_AUTH_RU_OPTIONS_KEY, array() );
        add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );
        if ( empty( $this->settings['max_enabled'] ) ) return;
        add_action( 'login_form',            array( $this, 'render_button_wp' ) );
        add_action( 'register_form',         array( $this, 'render_button_wp' ) );
        add_action( 'login_enqueue_scripts', array( $this, 'output_styles' ) );
        add_action( 'login_message',         array( $this, 'show_error' ) );
        if ( class_exists( 'WooCommerce' ) ) {
            add_action( 'woocommerce_login_form_start',     array( $this, 'render_button_woo' ) );
            add_action( 'woocommerce_register_form_start',  array( $this, 'render_button_woo' ) );
            add_action( 'woocommerce_before_checkout_form', array( $this, 'render_checkout_banner' ) );
        }
        add_action( 'wp_head',   array( $this, 'maybe_output_frontend_styles' ) );
        add_action( 'wp_footer', array( $this, 'inject_miniapp_js' ) );
    }

    public function register_rest_routes() {
        register_rest_route( self::REST_NAMESPACE, '/max/validate', array(
            'methods' => 'POST', 'callback' => array( $this, 'rest_validate_initdata' ), 'permission_callback' => '__return_true',
        ) );
    }

    // ─── HMAC-SHA256 валидация initData ──────────────────────────────────────

    private function validate_init_data( $init_data_raw ) {
        $bot_token = trim( $this->settings['max_bot_token'] ?? '' );
        if ( empty( $bot_token ) || empty( $init_data_raw ) ) return false;

        $params = array();
        parse_str( $init_data_raw, $params );

        $provided_hash = $params['hash'] ?? '';
        if ( empty( $provided_hash ) ) return false;
        unset( $params['hash'] );

        if ( ! empty( $params['auth_date'] ) && ( time() - (int) $params['auth_date'] ) > 3600 ) {
            WP_Auth_Ru_Logger::log( 'WARNING', 'max', 'initData просрочен: auth_date=' . $params['auth_date'] );
            return false;
        }

        ksort( $params );
        $data_check_string = implode( "\n", array_map( function( $k, $v ) { return "$k=$v"; }, array_keys( $params ), array_values( $params ) ) );
        $secret_key    = hash_hmac( 'sha256', $bot_token, 'WebAppData', true );
        $expected_hash = hash_hmac( 'sha256', $data_check_string, $secret_key );

        return hash_equals( $expected_hash, $provided_hash );
    }

    private function extract_user_from_initdata( $init_data_raw ) {
        $params = array();
        parse_str( $init_data_raw, $params );
        $user_json = $params['user'] ?? '';
        if ( empty( $user_json ) ) return null;
        $user = json_decode( $user_json, true );
        return is_array( $user ) ? $user : null;
    }

    // ─── REST: валидация initData ─────────────────────────────────────────────

    public function rest_validate_initdata( WP_REST_Request $request ) {
        $nonce = sanitize_text_field( $request->get_param( 'nonce' ) ?? '' );
        if ( ! wp_verify_nonce( $nonce, self::NONCE_ACTION ) ) {
            WP_Auth_Ru_Logger::log( 'WARNING', 'max', 'Неверный nonce при валидации initData', array( 'ip' => $_SERVER['REMOTE_ADDR'] ?? '' ) );
            return new WP_REST_Response( array( 'success' => false, 'message' => 'Security check failed' ), 403 );
        }

        if ( is_user_logged_in() ) {
            return new WP_REST_Response( array( 'success' => true, 'redirect' => home_url() ) );
        }

        $raw = sanitize_text_field( $request->get_param( 'init_data' ) ?? '' );
        if ( empty( $raw ) ) {
            WP_Auth_Ru_Logger::log( 'WARNING', 'max', 'Пустой init_data' );
            return new WP_REST_Response( array( 'success' => false, 'message' => 'init_data is empty' ), 400 );
        }

        WP_Auth_Ru_Logger::log( 'INFO', 'max', 'Получен initData, проверка подписи HMAC-SHA256' );

        if ( ! $this->validate_init_data( $raw ) ) {
            WP_Auth_Ru_Logger::log( 'ERROR', 'max', 'Неверная подпись MAX initData — отклонено' );
            return new WP_REST_Response( array( 'success' => false, 'message' => 'Invalid MAX signature' ), 403 );
        }

        $user_info = $this->extract_user_from_initdata( $raw );
        if ( empty( $user_info ) ) {
            WP_Auth_Ru_Logger::log( 'ERROR', 'max', 'В initData нет данных пользователя' );
            return new WP_REST_Response( array( 'success' => false, 'message' => 'No user data in initData' ), 400 );
        }

        $user_id = $this->login_or_create_user( $user_info );
        if ( is_wp_error( $user_id ) ) {
            WP_Auth_Ru_Logger::log( 'ERROR', 'max', 'Ошибка создания/входа: ' . $user_id->get_error_message() );
            return new WP_REST_Response( array( 'success' => false, 'message' => $user_id->get_error_message() ), 500 );
        }

        wp_set_current_user( $user_id );
        wp_set_auth_cookie( $user_id, true );
        $user_obj = get_userdata( $user_id );
        if ( $user_obj ) do_action( 'wp_login', $user_obj->user_login, $user_obj );

        $redirect = home_url();
        $candidate = esc_url_raw( $request->get_param( 'redirect' ) ?? '' );
        if ( $candidate && strpos( $candidate, home_url() ) === 0 ) $redirect = $candidate;

        return new WP_REST_Response( array( 'success' => true, 'redirect' => $redirect ) );
    }

    // ─── Создание / вход пользователя ────────────────────────────────────────

    private function login_or_create_user( $user_info ) {
        $max_id  = (string) ( $user_info['id'] ?? '' );
        $fname   = sanitize_text_field( $user_info['first_name'] ?? '' );
        $lname   = sanitize_text_field( $user_info['last_name']  ?? '' );
        $uname   = sanitize_text_field( $user_info['username']   ?? '' );
        $display = trim( $fname . ' ' . $lname ) ?: $uname ?: 'MAX Пользователь';

        if ( $max_id ) {
            $found = get_users( array( 'meta_key' => self::STATE_META_KEY, 'meta_value' => $max_id, 'number' => 1, 'fields' => 'ids' ) );
            if ( ! empty( $found ) ) {
                $uid = (int) $found[0];
                wp_update_user( array( 'ID' => $uid, 'display_name' => $display, 'first_name' => $fname, 'last_name' => $lname ) );
                WP_Auth_Ru_Logger::log( 'SUCCESS', 'max', 'Вход: пользователь #' . $uid . ' (MAX ID: ' . $max_id . ')' );
                return $uid;
            }
        }

        $username = $this->make_unique_username( $uname ?: $display );
        $user_id  = wp_insert_user( array(
            'user_login'   => $username,
            'user_pass'    => wp_generate_password( 24, true, true ),
            'display_name' => $display,
            'first_name'   => $fname,
            'last_name'    => $lname,
            'role'         => get_option( 'default_role', 'subscriber' ),
        ) );

        if ( is_wp_error( $user_id ) ) {
            WP_Auth_Ru_Logger::log( 'ERROR', 'max', 'Ошибка создания пользователя: ' . $user_id->get_error_message() );
            return $user_id;
        }

        if ( $max_id ) update_user_meta( $user_id, self::STATE_META_KEY, $max_id );
        update_user_meta( $user_id, 'wp_auth_ru_provider', 'max' );
        WP_Auth_Ru_Logger::log( 'SUCCESS', 'max', 'Регистрация: новый пользователь #' . $user_id . ' (MAX ID: ' . $max_id . ')' );
        return $user_id;
    }

    private function make_unique_username( $base_name ) {
        $base = sanitize_user( strtolower( str_replace( array( ' ', '-', '.' ), '_', $base_name ) ), true );
        if ( empty( $base ) ) $base = 'max_user';
        $username = $base; $i = 1;
        while ( username_exists( $username ) ) $username = $base . '_' . $i++;
        return $username;
    }

    private function get_bot_url() {
        $username = trim( $this->settings['max_bot_username'] ?? '' );
        return $username ? 'https://max.ru/' . ltrim( $username, '@' ) : '';
    }

    private function icon() {
        return '<img src="' . esc_url( WP_AUTH_RU_PLUGIN_URL . 'assets/Image/MAX.svg' ) . '" class="wp-auth-ru-icon" alt="MAX" width="22" height="22">';
    }

    public function render_button_wp() {
        $bot_url = $this->get_bot_url();
        ?><div class="wp-auth-ru-wrap"><?php if ( $bot_url ) : ?><a href="<?php echo esc_url( $bot_url ); ?>" class="wp-auth-ru-btn wp-auth-ru-btn--max" target="_blank" rel="noopener noreferrer"><?php echo $this->icon(); ?> Войти через MAX</a><?php else : ?><span class="wp-auth-ru-btn wp-auth-ru-btn--max wp-auth-ru-btn--disabled"><?php echo $this->icon(); ?> Войти через MAX</span><?php endif; ?><p class="wp-auth-ru-hint">Откройте сайт через бота в MAX — вход произойдёт автоматически</p><div class="wp-auth-ru-divider"><span>или</span></div></div><?php
    }

    public function render_button_woo() {
        if ( is_user_logged_in() ) return;
        $bot_url = $this->get_bot_url();
        ?><div class="wp-auth-ru-wrap wp-auth-ru-wrap--woo"><?php if ( $bot_url ) : ?><a href="<?php echo esc_url( $bot_url ); ?>" class="wp-auth-ru-btn wp-auth-ru-btn--max" target="_blank" rel="noopener noreferrer"><?php echo $this->icon(); ?> Войти через MAX</a><?php else : ?><span class="wp-auth-ru-btn wp-auth-ru-btn--max wp-auth-ru-btn--disabled"><?php echo $this->icon(); ?> Войти через MAX</span><?php endif; ?><p class="wp-auth-ru-hint">Откройте сайт через бота в MAX — вход произойдёт автоматически</p><div class="wp-auth-ru-divider"><span>или</span></div></div><?php
    }

    public function render_checkout_banner() {
        if ( is_user_logged_in() ) return;
        $bot_url = $this->get_bot_url();
        if ( empty( $bot_url ) ) return;
        ?><div class="wp-auth-ru-checkout-banner" style="border-color:#c0c8ff;background:#f0f2ff;"><p class="wp-auth-ru-checkout-title">Быстрый вход перед оформлением:</p><a href="<?php echo esc_url( $bot_url ); ?>" class="wp-auth-ru-btn wp-auth-ru-btn--max wp-auth-ru-btn--checkout" target="_blank" rel="noopener noreferrer"><?php echo $this->icon(); ?> Войти через MAX</a><p class="wp-auth-ru-hint">Откройте сайт через бота MAX — вход произойдёт автоматически</p></div><?php
    }

    public function inject_miniapp_js() {
        if ( is_user_logged_in() ) return;
        $nonce    = wp_create_nonce( self::NONCE_ACTION );
        $rest_url = rest_url( self::REST_NAMESPACE . '/max/validate' );
        ?>
<script id="wp-auth-ru-max-js">
(function(){
    'use strict';
    var REST_URL = <?php echo wp_json_encode( $rest_url ); ?>;
    var NONCE    = <?php echo wp_json_encode( $nonce ); ?>;
    var initData = null;
    if (window.MaxApp && typeof window.MaxApp.initData === 'string' && window.MaxApp.initData) initData = window.MaxApp.initData;
    if (!initData && window.Telegram && window.Telegram.WebApp && window.Telegram.WebApp.initData) initData = window.Telegram.WebApp.initData;
    if (!initData) return;
    var fd = new FormData();
    fd.append('nonce', NONCE);
    fd.append('init_data', initData);
    fd.append('redirect', window.location.href);
    fetch(REST_URL, { method: 'POST', body: fd, credentials: 'same-origin' })
        .then(function(r){ return r.json(); })
        .then(function(resp){ if (resp && resp.success && resp.redirect) window.location.href = resp.redirect; })
        .catch(function(){});
})();
</script>
        <?php
    }

    public function show_error( $message ) {
        if ( ! empty( $_GET['max_oauth_error'] ) ) {
            $err = sanitize_text_field( wp_unslash( $_GET['max_oauth_error'] ) );
            $message .= '<p class="message" style="color:#d63638;background:#fff3f3;padding:8px 12px;border-radius:4px;margin-top:8px;"><strong>Ошибка входа через MAX:</strong> ' . esc_html( $err ) . '</p>';
        }
        return $message;
    }

    public function maybe_output_frontend_styles() {
        if ( ( function_exists( 'is_account_page' ) && is_account_page() ) || ( function_exists( 'is_checkout' ) && is_checkout() ) ) $this->output_styles();
    }

    public function output_styles() {
        static $printed = false;
        if ( $printed ) return; $printed = true;
        ?><style id="wp-auth-ru-max-styles">.wp-auth-ru-btn--max{background:linear-gradient(135deg,#4ccfff 0%,#5533ee 66%,#9933dd 100%);box-shadow:0 2px 10px rgba(85,51,238,.35)}.wp-auth-ru-btn--disabled{opacity:.55;cursor:default;pointer-events:none}</style><?php
    }
}
