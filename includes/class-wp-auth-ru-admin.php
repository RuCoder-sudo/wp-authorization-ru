<?php
/**
 * Страница настроек плагина WP Authorization RU в панели WordPress.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WP_Auth_Ru_Admin {

    private static $instance = null;

    public static function instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        add_action( 'admin_menu', array( $this, 'add_menu' ) );
        add_action( 'admin_init', array( $this, 'register_settings' ) );
        add_action( 'admin_notices', array( $this, 'maybe_show_setup_notice' ) );
    }

    public function add_menu() {
        add_options_page(
            'WP Authorization RU',
            'Авторизация RU',
            'manage_options',
            'wp-authorization-ru',
            array( $this, 'render_settings_page' )
        );
    }

    public function register_settings() {
        register_setting(
            'wp_authorization_ru_group',
            WP_AUTH_RU_OPTIONS_KEY,
            array( 'sanitize_callback' => array( $this, 'sanitize_settings' ) )
        );
    }

    public function sanitize_settings( $input ) {
        $clean = array();

        $text_fields = array(
            'yandex_enabled',
            'yandex_client_id',
            'yandex_client_secret',
            'mailru_enabled',
            'mailru_client_id',
            'mailru_client_secret',
        );

        foreach ( $text_fields as $field ) {
            $clean[ $field ] = isset( $input[ $field ] ) ? sanitize_text_field( $input[ $field ] ) : '';
        }

        return $clean;
    }

    /**
     * Показываем уведомление, если ни один провайдер не настроен.
     */
    public function maybe_show_setup_notice() {
        $screen = get_current_screen();
        if ( $screen && 'settings_page_wp-authorization-ru' === $screen->id ) {
            return;
        }
        $opts = get_option( WP_AUTH_RU_OPTIONS_KEY, array() );
        $yandex_ok = ! empty( $opts['yandex_enabled'] ) && ! empty( $opts['yandex_client_id'] ) && ! empty( $opts['yandex_client_secret'] );
        $mailru_ok  = ! empty( $opts['mailru_enabled'] )  && ! empty( $opts['mailru_client_id'] )  && ! empty( $opts['mailru_client_secret'] );
        if ( ! $yandex_ok && ! $mailru_ok ) {
            $url = admin_url( 'options-general.php?page=wp-authorization-ru' );
            echo '<div class="notice notice-info is-dismissible"><p>'
                . '🔐 <strong>WP Authorization RU:</strong> '
                . 'Ни один OAuth-провайдер не настроен. '
                . '<a href="' . esc_url( $url ) . '">Перейти к настройкам</a>.'
                . '</p></div>';
        }
    }

    public function render_settings_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $opts = get_option( WP_AUTH_RU_OPTIONS_KEY, array() );

        $yandex_callback = WP_Auth_Ru_Yandex::get_callback_url();
        $mailru_callback = WP_Auth_Ru_Mailru::get_callback_url();
        ?>
        <div class="wrap">
            <h1>WP Authorization RU — Настройки</h1>
            <p style="color:#555;max-width:700px;">
                Плагин добавляет кнопки «Войти через Яндекс» и «Войти через Mail.ru» на страницы
                входа / регистрации WordPress и WooCommerce, а также на страницу оформления заказа.
            </p>

            <form method="post" action="options.php">
                <?php settings_fields( 'wp_authorization_ru_group' ); ?>

                <!-- ═══ ЯНДЕКС ═══════════════════════════════════════════ -->
                <h2 style="margin-top:30px;border-bottom:2px solid #fc3f1d;padding-bottom:8px;color:#fc3f1d;">
                    🟠 Яндекс ID (Яндекс OAuth)
                </h2>

                <div style="background:#fff8f6;border:1px solid #ffd0c0;border-radius:8px;padding:16px 20px;margin-bottom:20px;max-width:700px;">
                    <strong>Как получить Client ID и Client Secret:</strong>
                    <ol style="margin:8px 0 0 18px;color:#555;">
                        <li>Откройте <a href="https://oauth.yandex.ru/" target="_blank" rel="noopener">oauth.yandex.ru</a> → «Зарегистрировать приложение».</li>
                        <li>Тип платформы: <strong>Веб-сервисы</strong>.</li>
                        <li>Права доступа: <code>login:info</code>, <code>login:email</code>.</li>
                        <li>Callback URI: скопируйте строку ниже и вставьте в поле «Redirect URI».</li>
                    </ol>
                    <p style="margin:10px 0 0;">
                        <strong>Redirect URI для Яндекс:</strong><br>
                        <code style="background:#fff;padding:4px 8px;border:1px solid #ddd;border-radius:4px;display:inline-block;margin-top:4px;word-break:break-all;">
                            <?php echo esc_html( $yandex_callback ); ?>
                        </code>
                        <button type="button" onclick="navigator.clipboard.writeText('<?php echo esc_js( $yandex_callback ); ?>');this.textContent='Скопировано ✓'" style="margin-left:8px;padding:3px 10px;cursor:pointer;">Копировать</button>
                    </p>
                </div>

                <table class="form-table" role="presentation">
                    <tr>
                        <th><label for="yandex_enabled">Включить Яндекс OAuth</label></th>
                        <td>
                            <label>
                                <input type="checkbox" id="yandex_enabled"
                                    name="<?php echo esc_attr( WP_AUTH_RU_OPTIONS_KEY ); ?>[yandex_enabled]"
                                    value="1"
                                    <?php checked( ! empty( $opts['yandex_enabled'] ) ); ?>>
                                Показывать кнопку «Войти через Яндекс»
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="yandex_client_id">Client ID</label></th>
                        <td>
                            <input type="text" id="yandex_client_id"
                                name="<?php echo esc_attr( WP_AUTH_RU_OPTIONS_KEY ); ?>[yandex_client_id]"
                                value="<?php echo esc_attr( $opts['yandex_client_id'] ?? '' ); ?>"
                                class="regular-text" autocomplete="off" placeholder="Например: 1234567890abcdef">
                        </td>
                    </tr>
                    <tr>
                        <th><label for="yandex_client_secret">Client Secret</label></th>
                        <td>
                            <input type="password" id="yandex_client_secret"
                                name="<?php echo esc_attr( WP_AUTH_RU_OPTIONS_KEY ); ?>[yandex_client_secret]"
                                value="<?php echo esc_attr( $opts['yandex_client_secret'] ?? '' ); ?>"
                                class="regular-text" autocomplete="new-password">
                        </td>
                    </tr>
                </table>

                <!-- ═══ MAIL.RU ═══════════════════════════════════════════ -->
                <h2 style="margin-top:30px;border-bottom:2px solid #005ff9;padding-bottom:8px;color:#005ff9;">
                    🔵 Mail.ru OAuth (VK ID / Mail.ru)
                </h2>

                <div style="background:#f0f4ff;border:1px solid #b8d0ff;border-radius:8px;padding:16px 20px;margin-bottom:20px;max-width:700px;">
                    <strong>Как получить Client ID и Client Secret:</strong>
                    <ol style="margin:8px 0 0 18px;color:#555;">
                        <li>Откройте <a href="https://o2.mail.ru/app/" target="_blank" rel="noopener">o2.mail.ru/app</a> → «Добавить приложение».</li>
                        <li>Тип приложения: <strong>Сайт</strong>.</li>
                        <li>Права: <code>userinfo</code> (добавляется автоматически).</li>
                        <li>Callback URI: скопируйте строку ниже и вставьте в поле «URL-адреса для перенаправления».</li>
                    </ol>
                    <p style="margin:10px 0 0;">
                        <strong>Redirect URI для Mail.ru:</strong><br>
                        <code style="background:#fff;padding:4px 8px;border:1px solid #ddd;border-radius:4px;display:inline-block;margin-top:4px;word-break:break-all;">
                            <?php echo esc_html( $mailru_callback ); ?>
                        </code>
                        <button type="button" onclick="navigator.clipboard.writeText('<?php echo esc_js( $mailru_callback ); ?>');this.textContent='Скопировано ✓'" style="margin-left:8px;padding:3px 10px;cursor:pointer;">Копировать</button>
                    </p>
                </div>

                <table class="form-table" role="presentation">
                    <tr>
                        <th><label for="mailru_enabled">Включить Mail.ru OAuth</label></th>
                        <td>
                            <label>
                                <input type="checkbox" id="mailru_enabled"
                                    name="<?php echo esc_attr( WP_AUTH_RU_OPTIONS_KEY ); ?>[mailru_enabled]"
                                    value="1"
                                    <?php checked( ! empty( $opts['mailru_enabled'] ) ); ?>>
                                Показывать кнопку «Войти через Mail.ru»
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="mailru_client_id">Client ID</label></th>
                        <td>
                            <input type="text" id="mailru_client_id"
                                name="<?php echo esc_attr( WP_AUTH_RU_OPTIONS_KEY ); ?>[mailru_client_id]"
                                value="<?php echo esc_attr( $opts['mailru_client_id'] ?? '' ); ?>"
                                class="regular-text" autocomplete="off" placeholder="Например: 1234567890">
                        </td>
                    </tr>
                    <tr>
                        <th><label for="mailru_client_secret">Client Secret</label></th>
                        <td>
                            <input type="password" id="mailru_client_secret"
                                name="<?php echo esc_attr( WP_AUTH_RU_OPTIONS_KEY ); ?>[mailru_client_secret]"
                                value="<?php echo esc_attr( $opts['mailru_client_secret'] ?? '' ); ?>"
                                class="regular-text" autocomplete="new-password">
                        </td>
                    </tr>
                </table>

                <?php submit_button( 'Сохранить настройки' ); ?>
            </form>

            <hr style="margin-top:30px;">
            <p style="color:#888;font-size:13px;">
                WP Authorization RU v<?php echo esc_html( WP_AUTH_RU_VERSION ); ?> |
                <a href="https://рукодер.рф/" target="_blank" rel="noopener">РуКодер</a>
            </p>
        </div>
        <?php
    }
}
