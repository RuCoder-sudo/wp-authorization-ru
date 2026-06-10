<?php
/**
 * Соответствие российскому законодательству об авторизации.
 *
 * ── Закон ────────────────────────────────────────────────────────────────────
 *  Госдума приняла поправки в КоАП РФ, устанавливающие административную
 *  ответственность за авторизацию пользователей через иностранные сервисы:
 *    • Граждане:        10 000 — 20 000 руб.
 *    • Должностные лица: 30 000 — 50 000 руб.
 *    • Юридические лица: 500 000 — 700 000 руб.
 *
 *  По действующему законодательству авторизация в РФ должна проводиться через:
 *    – Российский номер телефона
 *    – Единый портал Госуслуг (ЕСИА)
 *    – Единую биометрическую систему
 *    – Иную ИС, владелец которой — гражданин РФ или российское юридическое лицо
 *
 * ── Что делает этот класс ────────────────────────────────────────────────────
 *  1. Определяет активные плагины иностранной авторизации (Google, Facebook и др.)
 *     и показывает предупреждение в панели администратора.
 *  2. При включённом «Режиме соответствия» блокирует вход и регистрацию,
 *     если пользователь авторизовался через иностранный сервис (определяется
 *     по user_meta, которые ставят сторонние плагины социального входа).
 *  3. Отмечает пользователей, созданных через разрешённые российские провайдеры.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WP_Auth_Ru_Compliance {

    private static $instance = null;
    private $settings;

    /**
     * Известные плагины иностранной OAuth-авторизации.
     * Формат: 'slug/file.php' => 'Название'
     */
    private static $foreign_plugins = array(
        'nextend-social-login/nextend-social-login.php'                          => 'Nextend Social Login (Google, Facebook, Apple)',
        'nextend-social-login-pro/nextend-social-login-pro.php'                  => 'Nextend Social Login Pro',
        'miniorange-google-login/google_signon.php'                              => 'Google Login (miniOrange)',
        'google-login/google-login.php'                                          => 'Google Login by WPBrigade',
        'woocommerce-social-login/woocommerce-social-login.php'                  => 'WooCommerce Social Login (SkyVerge)',
        'super-socializer/super-socializer.php'                                  => 'Super Socializer',
        'social-login/social-login.php'                                          => 'Social Login',
        'loginpress/loginpress.php'                                              => 'LoginPress (социальный вход)',
        'wordpress-social-login/wordpress-social-login.php'                      => 'WordPress Social Login',
        'instagram-feed/instagram-feed.php'                                      => 'Instagram Auth',
        'facebook-for-woocommerce/facebook-for-woocommerce.php'                  => 'Facebook for WooCommerce',
        'affiliate-wp/affiliate-wp.php'                                          => 'AffiliateWP Social Auth',
        'woo-social-login/woo-social-login.php'                                  => 'Woo Social Login',
        'heateor-super-socializer/heateor-super-socializer.php'                  => 'Heateor Super Socializer',
        'login-with-google/login-with-google.php'                                => 'Login with Google',
        'easy-google-login/easy-google-login.php'                                => 'Easy Google Login',
        'google-authenticator/google-authenticator.php'                          => 'Google Authenticator (2FA)',
        'woocommerce-google-login/woocommerce-google-login.php'                  => 'WooCommerce Google Login',
    );

    /**
     * User meta, которые ставят сторонние плагины при входе через иностранные сервисы.
     * Используем для определения «иностранных» пользователей.
     */
    private static $foreign_meta_keys = array(
        'nextend_auth_provider',        // Nextend Social Login
        'nsl_provider',                 // Nextend
        'nsl_access_token',             // Nextend
        'facebook_profile',             // Facebook Login
        'fb_profile',                   // Facebook
        'google_profile',               // Google Login
        '_social_login_provider',       // WooCommerce Social Login
        'wsl_current_provider',         // WordPress Social Login
        'heateor_ss_access_token',      // Heateor Super Socializer
        'social_login_provider',        // Generic
        '_google_auth_login',           // Google
    );

    public static function instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->settings = get_option( WP_AUTH_RU_OPTIONS_KEY, array() );

        // Всегда показываем предупреждения об иностранных плагинах
        add_action( 'admin_notices', array( $this, 'warn_foreign_plugins' ) );

        // Режим соответствия: блокируем вход через иностранные сервисы
        if ( ! empty( $this->settings['compliance_mode'] ) ) {
            add_action( 'wp_login',      array( $this, 'block_foreign_login' ), 1, 2 );
            add_action( 'user_register', array( $this, 'maybe_block_foreign_registration' ), 1 );
            add_filter( 'wp_authenticate_user', array( $this, 'check_foreign_user' ), 99 );
        }
    }

    // ─── Обнаружение иностранных плагинов ────────────────────────────────────

    public static function get_active_foreign_plugins() {
        $active = get_option( 'active_plugins', array() );
        // Сеть
        if ( is_multisite() ) {
            $network = array_keys( get_site_option( 'active_sitewide_plugins', array() ) );
            $active  = array_merge( $active, $network );
        }

        $found = array();
        foreach ( self::$foreign_plugins as $slug => $name ) {
            if ( in_array( $slug, $active, true ) ) {
                $found[ $slug ] = $name;
            }
        }
        return $found;
    }

    // ─── Admin notice об иностранных плагинах ─────────────────────────────────

    public function warn_foreign_plugins() {
        if ( ! current_user_can( 'manage_options' ) ) return;

        $foreign = self::get_active_foreign_plugins();
        if ( empty( $foreign ) ) return;

        $list = implode( ', ', array_values( $foreign ) );
        $url  = admin_url( 'options-general.php?page=wp-authorization-ru' );
        ?>
        <div class="notice notice-error">
            <p>
                <strong>⚠️ WP Authorization RU — Нарушение законодательства РФ!</strong><br>
                На сайте активны плагины авторизации через <strong>иностранные сервисы</strong>:
                <em><?php echo esc_html( $list ); ?></em><br>
                Согласно поправкам в КоАП РФ, авторизация через иностранные сервисы на территории РФ
                влечёт штраф <strong>до 700 000 руб.</strong> для юридических лиц.
                Деактивируйте эти плагины и используйте только российские провайдеры.
                <a href="<?php echo esc_url( $url ); ?>">Перейти к настройкам авторизации</a>.
            </p>
        </div>
        <?php
    }

    // ─── Блокировка входа через иностранные сервисы ───────────────────────────

    public function check_foreign_user( $user ) {
        if ( is_wp_error( $user ) || ! ( $user instanceof WP_User ) ) {
            return $user;
        }

        if ( $this->is_foreign_user( $user->ID ) ) {
            WP_Auth_Ru_Logger::log( 'WARNING', 'compliance', 'Заблокирован вход через иностранный сервис (check_foreign_user): #' . $user->ID . ' ' . $user->user_login );
            return new WP_Error(
                'wp_auth_ru_foreign_blocked',
                '<strong>Вход заблокирован.</strong> Авторизация через иностранные сервисы ' .
                'запрещена на данном сайте в соответствии с требованиями законодательства РФ. ' .
                'Пожалуйста, используйте российский сервис (Яндекс ID, Mail.ru, ВКонтакте, Rambler или Госуслуги).'
            );
        }

        return $user;
    }

    public function block_foreign_login( $user_login, $user ) {
        if ( ! ( $user instanceof WP_User ) ) return;

        if ( $this->is_foreign_user( $user->ID ) ) {
            WP_Auth_Ru_Logger::log( 'WARNING', 'compliance', 'Заблокирован вход через иностранный сервис (wp_login): #' . $user->ID . ' ' . $user_login );
            wp_logout();
            wp_safe_redirect( add_query_arg(
                'login',
                'foreign_blocked',
                wp_login_url()
            ) );
            exit;
        }
    }

    public function maybe_block_foreign_registration( $user_id ) {
        if ( $this->is_foreign_user( $user_id ) ) {
            WP_Auth_Ru_Logger::log( 'WARNING', 'compliance', 'Заблокирована регистрация через иностранный сервис, пользователь #' . $user_id . ' удалён' );
            require_once ABSPATH . 'wp-admin/includes/user.php';
            wp_delete_user( $user_id );
        }
    }

    // ─── Проверка, создан ли пользователь через иностранный сервис ───────────

    public static function is_foreign_user( $user_id ) {
        foreach ( self::$foreign_meta_keys as $meta_key ) {
            if ( get_user_meta( $user_id, $meta_key, true ) ) {
                return true;
            }
        }

        $provider = get_user_meta( $user_id, 'wp_auth_ru_provider', true );
        if ( $provider && ! in_array( $provider, array( 'yandex', 'mailru', 'vk', 'rambler', 'max', 'gosuslugi' ), true ) ) {
            return true;
        }

        return false;
    }

    // ─── Публичный метод для страницы настроек ────────────────────────────────

    public static function get_foreign_plugins_list() {
        return self::$foreign_plugins;
    }
}
