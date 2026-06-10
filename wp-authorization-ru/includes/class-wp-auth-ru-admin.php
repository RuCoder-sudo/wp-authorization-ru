<?php
/**
 * Страница настроек WP Authorization RU.
 * Вкладки: Настройки | Журнал событий
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WP_Auth_Ru_Admin {

    private static $instance = null;

    public static function instance() {
        if ( null === self::$instance ) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        add_action( 'admin_menu',    array( $this, 'add_menu' ) );
        add_action( 'admin_init',    array( $this, 'register_settings' ) );
        add_action( 'admin_notices', array( $this, 'maybe_show_setup_notice' ) );
        add_action( 'login_message', array( $this, 'show_blocked_message' ) );
        // Очистка журнала
        add_action( 'admin_post_wp_auth_ru_clear_logs', array( $this, 'handle_clear_logs' ) );
    }

    public function add_menu() {
        add_options_page(
            'WP Authorization RU',
            'Авторизация RU',
            'manage_options',
            'wp-authorization-ru',
            array( $this, 'render_page' )
        );
    }

    public function register_settings() {
        register_setting( 'wp_authorization_ru_group', WP_AUTH_RU_OPTIONS_KEY,
            array( 'sanitize_callback' => array( $this, 'sanitize_settings' ) ) );
    }

    public function sanitize_settings( $input ) {
        $clean = array();
        $fields = array(
            'yandex_enabled',    'yandex_client_id',    'yandex_client_secret',
            'mailru_enabled',    'mailru_client_id',    'mailru_client_secret',
            'vk_enabled',        'vk_client_id',        'vk_client_secret',
            'rambler_enabled',   'rambler_client_id',   'rambler_client_secret',
            'max_enabled',       'max_bot_token',       'max_bot_username',
            'gosuslugi_enabled', 'gosuslugi_client_id', 'gosuslugi_client_secret', 'gosuslugi_test_mode',
            'compliance_mode',
        );
        foreach ( $fields as $f ) $clean[ $f ] = isset( $input[ $f ] ) ? sanitize_text_field( $input[ $f ] ) : '';
        return $clean;
    }

    public function maybe_show_setup_notice() {
        $screen = get_current_screen();
        if ( $screen && 'settings_page_wp-authorization-ru' === $screen->id ) return;
        $opts        = get_option( WP_AUTH_RU_OPTIONS_KEY, array() );
        $any_enabled = ! empty( $opts['yandex_enabled'] ) || ! empty( $opts['mailru_enabled'] ) ||
                       ! empty( $opts['vk_enabled'] )     || ! empty( $opts['rambler_enabled'] ) ||
                       ! empty( $opts['max_enabled'] )    || ! empty( $opts['gosuslugi_enabled'] );
        if ( ! $any_enabled ) {
            echo '<div class="notice notice-info is-dismissible"><p>🔐 <strong>WP Authorization RU:</strong> Ни один OAuth-провайдер не настроен. <a href="' . esc_url( admin_url( 'options-general.php?page=wp-authorization-ru' ) ) . '">Перейти к настройкам</a>.</p></div>';
        }
    }

    public function show_blocked_message( $message ) {
        if ( ! empty( $_GET['login'] ) && $_GET['login'] === 'foreign_blocked' ) {
            $message .= '<p class="message" style="color:#d63638;background:#fff3f3;padding:8px 12px;border-radius:4px;margin-top:8px;"><strong>Вход заблокирован.</strong> Авторизация через иностранные сервисы запрещена. Используйте Яндекс ID, Mail.ru, ВКонтакте, Rambler или Госуслуги.</p>';
        }
        return $message;
    }

    public function handle_clear_logs() {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Нет прав' );
        check_admin_referer( 'wp_auth_ru_clear_logs' );
        WP_Auth_Ru_Logger::clear_logs();
        wp_safe_redirect( admin_url( 'options-general.php?page=wp-authorization-ru&tab=logs&cleared=1' ) );
        exit;
    }

    // ─── Роутер страниц ────────────────────────────────────────────────────────

    public function render_page() {
        if ( ! current_user_can( 'manage_options' ) ) return;
        $tab = sanitize_key( $_GET['tab'] ?? 'settings' );
        ?>
        <div class="wrap">
            <h1 style="display:flex;align-items:center;gap:10px;">🔐 WP Authorization RU <span style="font-size:13px;font-weight:400;color:#888;background:#f0f0f0;padding:2px 10px;border-radius:20px;">v<?php echo esc_html( WP_AUTH_RU_VERSION ); ?></span></h1>

            <?php /* Таб-навигация */ ?>
            <nav class="nav-tab-wrapper" style="margin-bottom:20px;">
                <a href="<?php echo esc_url( admin_url( 'options-general.php?page=wp-authorization-ru&tab=settings' ) ); ?>"
                   class="nav-tab <?php echo $tab === 'settings' ? 'nav-tab-active' : ''; ?>">⚙️ Настройки</a>
                <a href="<?php echo esc_url( admin_url( 'options-general.php?page=wp-authorization-ru&tab=logs' ) ); ?>"
                   class="nav-tab <?php echo $tab === 'logs' ? 'nav-tab-active' : ''; ?>">
                    📋 Журнал событий
                    <?php
                    $stats = WP_Auth_Ru_Logger::get_stats();
                    if ( $stats['error'] > 0 ) {
                        echo '<span style="margin-left:5px;background:#d63638;color:#fff;border-radius:10px;padding:1px 7px;font-size:11px;">' . (int) $stats['error'] . ' ошибок</span>';
                    }
                    ?>
                </a>
            </nav>

            <?php
            if ( $tab === 'logs' ) {
                $this->render_logs_tab();
            } else {
                $this->render_settings_tab();
            }
            ?>
        </div>
        <?php
    }

    // ─── Вкладка: Журнал ───────────────────────────────────────────────────────

    private function render_logs_tab() {
        $stats = WP_Auth_Ru_Logger::get_stats();
        $logs  = WP_Auth_Ru_Logger::get_logs();

        if ( ! empty( $_GET['cleared'] ) ) {
            echo '<div class="notice notice-success is-dismissible"><p>Журнал очищен.</p></div>';
        }

        $level_colors = array(
            'SUCCESS' => array( 'bg' => '#f0fff4', 'border' => '#22c55e', 'badge' => '#16a34a', 'text' => '#166534' ),
            'ERROR'   => array( 'bg' => '#fff0f0', 'border' => '#ef4444', 'badge' => '#dc2626', 'text' => '#991b1b' ),
            'WARNING' => array( 'bg' => '#fffbeb', 'border' => '#f59e0b', 'badge' => '#d97706', 'text' => '#92400e' ),
            'INFO'    => array( 'bg' => '#f0f9ff', 'border' => '#38bdf8', 'badge' => '#0284c7', 'text' => '#075985' ),
        );

        $provider_labels = array(
            'yandex'    => '🟠 Яндекс',
            'mailru'    => '🔵 Mail.ru',
            'vk'        => '💙 ВКонтакте',
            'rambler'   => '🔷 Rambler',
            'max'       => '🟣 MAX',
            'gosuslugi' => '🏛️ Госуслуги',
            'system'    => '⚙️ Система',
            'compliance'=> '🛡️ Блокировка',
        );

        ?>
        <style>
        .wpar-stat { display:inline-flex;flex-direction:column;align-items:center;padding:12px 20px;border-radius:10px;min-width:90px;text-align:center; }
        .wpar-stat-n { font-size:28px;font-weight:700;line-height:1; }
        .wpar-stat-l { font-size:11px;margin-top:3px;opacity:.75; }
        .wpar-log-row { display:flex;gap:8px;align-items:flex-start;padding:7px 10px;border-radius:6px;margin-bottom:4px;border-left:3px solid; }
        .wpar-log-time { font-size:11px;color:#888;white-space:nowrap;min-width:130px;padding-top:1px; }
        .wpar-log-badge { font-size:10px;font-weight:700;padding:1px 7px;border-radius:10px;white-space:nowrap;color:#fff;min-width:62px;text-align:center; }
        .wpar-log-provider { font-size:11px;min-width:80px;white-space:nowrap; }
        .wpar-log-msg { font-size:13px;flex:1; }
        .wpar-log-ctx { font-size:10px;color:#888;margin-top:2px; }
        </style>

        <!-- Статистика -->
        <div style="display:flex;gap:12px;flex-wrap:wrap;margin:0 0 20px;">
            <div class="wpar-stat" style="background:#f3f4f6;border:1px solid #d1d5db;">
                <span class="wpar-stat-n"><?php echo (int) $stats['total']; ?></span>
                <span class="wpar-stat-l">Всего</span>
            </div>
            <div class="wpar-stat" style="background:#f0fff4;border:1px solid #86efac;">
                <span class="wpar-stat-n" style="color:#16a34a;"><?php echo (int) $stats['success']; ?></span>
                <span class="wpar-stat-l" style="color:#16a34a;">Успех</span>
            </div>
            <div class="wpar-stat" style="background:#fff0f0;border:1px solid #fca5a5;">
                <span class="wpar-stat-n" style="color:#dc2626;"><?php echo (int) $stats['error']; ?></span>
                <span class="wpar-stat-l" style="color:#dc2626;">Ошибки</span>
            </div>
            <div class="wpar-stat" style="background:#fffbeb;border:1px solid #fcd34d;">
                <span class="wpar-stat-n" style="color:#d97706;"><?php echo (int) $stats['warning']; ?></span>
                <span class="wpar-stat-l" style="color:#d97706;">Предупр.</span>
            </div>
            <div class="wpar-stat" style="background:#f0f9ff;border:1px solid #7dd3fc;">
                <span class="wpar-stat-n" style="color:#0284c7;"><?php echo (int) $stats['info']; ?></span>
                <span class="wpar-stat-l" style="color:#0284c7;">Инфо</span>
            </div>
        </div>

        <?php if ( ! empty( $stats['providers'] ) ) : ?>
        <!-- По провайдерам -->
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin:0 0 16px;">
            <?php foreach ( $stats['providers'] as $p => $ps ) : ?>
            <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:8px 14px;font-size:13px;">
                <?php echo esc_html( $provider_labels[ $p ] ?? ucfirst( $p ) ); ?>:
                <strong><?php echo (int) $ps['total']; ?></strong> всего,
                <span style="color:#16a34a;"><?php echo (int) $ps['success']; ?> ✓</span>
                <?php if ( $ps['error'] > 0 ) : ?>
                , <span style="color:#dc2626;"><?php echo (int) $ps['error']; ?> ✗</span>
                <?php endif; ?>
            </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>

        <!-- Кнопки управления -->
        <div style="display:flex;gap:10px;align-items:center;margin:0 0 16px;">
            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;">
                <input type="hidden" name="action" value="wp_auth_ru_clear_logs">
                <?php wp_nonce_field( 'wp_auth_ru_clear_logs' ); ?>
                <button type="submit" class="button button-secondary" onclick="return confirm('Очистить весь журнал?');">🗑️ Очистить журнал</button>
            </form>
            <button type="button" class="button" onclick="location.reload();">🔄 Обновить</button>
            <span style="color:#888;font-size:12px;">Хранится <?php echo WP_Auth_Ru_Logger::MAX_ENTRIES; ?> последних записей · Обновлено: <?php echo esc_html( current_time( 'H:i:s' ) ); ?></span>
        </div>

        <!-- Журнал -->
        <?php if ( empty( $logs ) ) : ?>
        <div style="background:#f9fafb;border:1px dashed #d1d5db;border-radius:8px;padding:40px;text-align:center;color:#6b7280;">
            <p style="font-size:16px;margin:0 0 8px;">📋 Журнал пуст</p>
            <p style="margin:0;font-size:13px;">События появятся, когда пользователи начнут входить через кнопки OAuth.</p>
        </div>
        <?php else : ?>
        <div style="max-height:600px;overflow-y:auto;border:1px solid #e5e7eb;border-radius:8px;padding:12px;background:#fafafa;">
            <?php foreach ( $logs as $entry ) :
                $level = strtoupper( $entry['level'] ?? 'INFO' );
                $c     = $level_colors[ $level ] ?? $level_colors['INFO'];
                $prov  = $entry['provider'] ?? '';
                $pname = $provider_labels[ $prov ] ?? ucfirst( $prov );
                ?>
            <div class="wpar-log-row" style="background:<?php echo esc_attr( $c['bg'] ); ?>;border-color:<?php echo esc_attr( $c['border'] ); ?>;">
                <span class="wpar-log-time"><?php echo esc_html( $entry['time'] ?? '' ); ?></span>
                <span class="wpar-log-badge" style="background:<?php echo esc_attr( $c['badge'] ); ?>;"><?php echo esc_html( $level ); ?></span>
                <span class="wpar-log-provider" style="color:<?php echo esc_attr( $c['text'] ); ?>;"><?php echo esc_html( $pname ); ?></span>
                <span class="wpar-log-msg">
                    <?php echo esc_html( $entry['msg'] ?? '' ); ?>
                    <?php if ( ! empty( $entry['ctx'] ) ) : ?>
                    <br><span class="wpar-log-ctx"><?php foreach ( $entry['ctx'] as $k => $v ) echo esc_html( $k ) . '=' . esc_html( $v ) . ' '; ?></span>
                    <?php endif; ?>
                </span>
            </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>

        <p style="color:#888;font-size:12px;margin-top:12px;">Email-адреса в журнале маскируются: <code>i***@ya.ru</code>. Журнал хранится в базе данных сайта и доступен только администраторам.</p>
        <?php
    }

    // ─── Вкладка: Настройки ────────────────────────────────────────────────────

    private function render_settings_tab() {
        $opts    = get_option( WP_AUTH_RU_OPTIONS_KEY, array() );
        $key     = WP_AUTH_RU_OPTIONS_KEY;
        $foreign = class_exists( 'WP_Auth_Ru_Compliance' ) ? WP_Auth_Ru_Compliance::get_active_foreign_plugins() : array();
        ?>

        <!-- Блок закона -->
        <div style="background:#fff8e6;border:2px solid #f0b429;border-radius:8px;padding:16px 20px;margin:0 0 20px;max-width:900px;">
            <h2 style="margin:0 0 10px;font-size:15px;color:#7a4a00;">⚠️ Штрафы за авторизацию через иностранные сервисы (до 700 000 руб.)</h2>
            <p style="margin:0 0 8px;font-size:13px;color:#555;line-height:1.6;">Госдума приняла поправки в КоАП РФ. Авторизация через Google, Apple, Facebook и другие иностранные сервисы запрещена. Используйте только российские провайдеры.</p>
            <table style="font-size:13px;border-collapse:collapse;width:100%;max-width:500px;">
                <tr style="background:#ffeeba;"><th style="padding:4px 10px;text-align:left;border:1px solid #f0d080;">Нарушитель</th><th style="padding:4px 10px;text-align:left;border:1px solid #f0d080;">Штраф</th></tr>
                <tr><td style="padding:4px 10px;border:1px solid #f0d080;">Граждане</td><td style="padding:4px 10px;border:1px solid #f0d080;">10 000 — 20 000 руб.</td></tr>
                <tr style="background:#fffdf0;"><td style="padding:4px 10px;border:1px solid #f0d080;">Должностные лица</td><td style="padding:4px 10px;border:1px solid #f0d080;">30 000 — 50 000 руб.</td></tr>
                <tr><td style="padding:4px 10px;border:1px solid #f0d080;"><strong>Юридические лица</strong></td><td style="padding:4px 10px;border:1px solid #f0d080;"><strong>500 000 — 700 000 руб.</strong></td></tr>
            </table>
            <p style="margin:8px 0 0;font-size:12px;color:#888;">Законопроект А. Горелкина (зам. председателя комитета ГД по информполитике). Принят во 2 и 3 чтениях.</p>
        </div>

        <?php if ( ! empty( $foreign ) ) : ?>
        <div style="background:#fff0f0;border:2px solid #d63638;border-radius:8px;padding:16px 20px;margin:0 0 20px;max-width:900px;">
            <h2 style="margin:0 0 8px;font-size:15px;color:#d63638;">🚫 Обнаружены плагины иностранной авторизации — деактивируйте их!</h2>
            <ul style="margin:0 0 8px;padding-left:20px;font-size:13px;color:#444;">
                <?php foreach ( $foreign as $slug => $name ) : ?>
                <li><strong><?php echo esc_html( $name ); ?></strong> <code style="font-size:11px;color:#888;">(<?php echo esc_html( $slug ); ?>)</code></li>
                <?php endforeach; ?>
            </ul>
            <a href="<?php echo esc_url( admin_url( 'plugins.php' ) ); ?>" class="button button-secondary">Управление плагинами</a>
        </div>
        <?php endif; ?>

        <form method="post" action="options.php">
            <?php settings_fields( 'wp_authorization_ru_group' ); ?>

            <!-- Режим соответствия -->
            <div style="background:#f0fff4;border:1px solid #4caf50;border-radius:8px;padding:14px 18px;margin:0 0 24px;max-width:900px;">
                <h2 style="margin:0 0 8px;font-size:14px;color:#2e7d32;">🛡️ Режим соответствия законодательству РФ</h2>
                <p style="margin:0 0 10px;font-size:13px;color:#444;">При включении — автоматически блокирует вход и регистрацию через иностранные OAuth-сервисы.</p>
                <label style="font-size:13px;font-weight:600;">
                    <input type="checkbox" name="<?php echo esc_attr( $key ); ?>[compliance_mode]" value="1" <?php checked( ! empty( $opts['compliance_mode'] ) ); ?>>
                    Включить блокировку иностранной авторизации
                </label>
            </div>

            <?php
            $providers = array(
                'yandex'    => array( 'label' => '🟠 Яндекс ID',     'color' => '#FC3F1D', 'btn' => 'Войти через Яндекс',    'creds' => true,  'note' => 'Зарегистрируйте приложение на <a href="https://oauth.yandex.ru/" target="_blank">oauth.yandex.ru</a>. Тип: <strong>Веб-сервисы</strong>. Права: <code>login:info</code>, <code>login:email</code>.',        'callback_fn' => 'WP_Auth_Ru_Yandex' ),
                'mailru'    => array( 'label' => '🔵 Mail.ru',         'color' => '#005FF9', 'btn' => 'Войти через Mail.ru',   'creds' => true,  'note' => 'Зарегистрируйте приложение на <a href="https://o2.mail.ru/app/" target="_blank">o2.mail.ru/app</a>. Тип: <strong>Сайт</strong>.',                                                                          'callback_fn' => 'WP_Auth_Ru_Mailru' ),
                'vk'        => array( 'label' => '💙 ВКонтакте',       'color' => '#5281B8', 'btn' => 'Войти через ВКонтакте', 'creds' => true,  'note' => 'Зарегистрируйте приложение на <a href="https://dev.vk.com/ru/admin/apps-list" target="_blank">dev.vk.com</a>. Тип: <strong>Веб-сайт</strong>. В настройках включите доступ к email.',              'callback_fn' => 'WP_Auth_Ru_VK' ),
                'rambler'   => array( 'label' => '🔷 Rambler',         'color' => '#1b35ba', 'btn' => 'Войти через Rambler',   'creds' => true,  'note' => 'Зарегистрируйте приложение на <a href="https://id.rambler.ru/apps" target="_blank">id.rambler.ru/apps</a>. Тип: <strong>Веб-сайт</strong>.',                                                              'callback_fn' => 'WP_Auth_Ru_Rambler' ),
            );

            foreach ( $providers as $pkey => $p ) :
                $cb_url = class_exists( $p['callback_fn'] ) ? call_user_func( array( $p['callback_fn'], 'get_callback_url' ) ) : '';
            ?>
            <h2 style="margin-top:24px;padding:10px 16px;background:rgba(0,0,0,.03);border-left:4px solid <?php echo esc_attr( $p['color'] ); ?>;border-radius:0 6px 6px 0;"><?php echo esc_html( $p['label'] ); ?></h2>
            <p><label><input type="checkbox" name="<?php echo esc_attr( $key ); ?>[<?php echo esc_attr( $pkey ); ?>_enabled]" value="1" <?php checked( ! empty( $opts[ $pkey . '_enabled' ] ) ); ?>> <strong>Включить «<?php echo esc_html( $p['btn'] ); ?>»</strong></label></p>
            <p style="color:#555;font-size:13px;margin:4px 0 10px;"><?php echo wp_kses_post( $p['note'] ); ?></p>
            <div style="background:#fafafa;border:1px solid #e0e0e0;border-radius:6px;padding:10px 14px;margin:0 0 12px;max-width:700px;">
                <strong>Redirect URI</strong> — скопируйте в настройки приложения у провайдера:<br>
                <code style="background:#fff;padding:3px 8px;border:1px solid #ddd;border-radius:4px;display:inline-block;margin-top:6px;word-break:break-all;font-size:13px;"><?php echo esc_html( $cb_url ); ?></code>
                <button type="button" onclick="navigator.clipboard.writeText('<?php echo esc_js( $cb_url ); ?>');this.textContent='Скопировано ✓'" style="margin-left:8px;padding:3px 10px;cursor:pointer;font-size:12px;">Копировать</button>
            </div>
            <table class="form-table" role="presentation" style="margin-top:0;">
                <tr><th style="width:160px;"><label>Client ID</label></th>
                    <td><input type="text" name="<?php echo esc_attr( $key ); ?>[<?php echo esc_attr( $pkey ); ?>_client_id]" value="<?php echo esc_attr( $opts[ $pkey . '_client_id' ] ?? '' ); ?>" class="regular-text" autocomplete="off"></td></tr>
                <tr><th><label>Client Secret</label></th>
                    <td><input type="password" name="<?php echo esc_attr( $key ); ?>[<?php echo esc_attr( $pkey ); ?>_client_secret]" value="<?php echo esc_attr( $opts[ $pkey . '_client_secret' ] ?? '' ); ?>" class="regular-text" autocomplete="new-password"></td></tr>
            </table>
            <?php endforeach; ?>

            <!-- MAX -->
            <h2 style="margin-top:24px;padding:10px 16px;background:rgba(0,0,0,.03);border-left:4px solid #5533ee;border-radius:0 6px 6px 0;">🟣 MAX Мессенджер</h2>
            <p><label><input type="checkbox" name="<?php echo esc_attr( $key ); ?>[max_enabled]" value="1" <?php checked( ! empty( $opts['max_enabled'] ) ); ?>> <strong>Включить «Войти через MAX»</strong></label></p>
            <div style="background:#f8f6ff;border:1px solid #d0c8ff;border-radius:6px;padding:12px 16px;margin:0 0 12px;max-width:700px;font-size:13px;color:#444;">
                <strong>⚠️ MAX использует Mini App, а не стандартный OAuth.</strong><br>
                1. Перейдите на <a href="https://max.ru/partner" target="_blank">max.ru/partner</a> → Чат-боты → «Интеграция» → получите <strong>Bot Token</strong>.<br>
                2. В «Мини-приложение» укажите URL вашего сайта.
            </div>
            <table class="form-table" role="presentation" style="margin-top:0;">
                <tr><th style="width:160px;"><label>Bot Token</label></th>
                    <td><input type="password" name="<?php echo esc_attr( $key ); ?>[max_bot_token]" value="<?php echo esc_attr( $opts['max_bot_token'] ?? '' ); ?>" class="regular-text" autocomplete="new-password"></td></tr>
                <tr><th><label>Username бота</label></th>
                    <td><input type="text" name="<?php echo esc_attr( $key ); ?>[max_bot_username]" value="<?php echo esc_attr( $opts['max_bot_username'] ?? '' ); ?>" class="regular-text" autocomplete="off" placeholder="@your_bot_username">
                    <p class="description">Кнопка ведёт на https://max.ru/your_bot_username</p></td></tr>
            </table>

            <!-- Госуслуги -->
            <?php $gs_url = class_exists( 'WP_Auth_Ru_Gosuslugi' ) ? WP_Auth_Ru_Gosuslugi::get_callback_url() : ''; ?>
            <h2 style="margin-top:24px;padding:10px 16px;background:rgba(0,0,0,.03);border-left:4px solid #1466AC;border-radius:0 6px 6px 0;">🏛️ Госуслуги (ЕСИА)</h2>
            <p><label><input type="checkbox" name="<?php echo esc_attr( $key ); ?>[gosuslugi_enabled]" value="1" <?php checked( ! empty( $opts['gosuslugi_enabled'] ) ); ?>> <strong>Включить «Войти через Госуслуги»</strong></label></p>
            <div style="background:#fff8e6;border:1px solid #ffe0a0;border-radius:6px;padding:10px 14px;margin:0 0 10px;max-width:700px;font-size:13px;color:#444;">
                <strong>⚠️ Только для юридических лиц (ИП, ООО) с УКЭП.</strong> Регистрация на <a href="https://esia.gosuslugi.ru/console/tech/" target="_blank">esia.gosuslugi.ru/console/tech/</a>.
            </div>
            <div style="background:#fafafa;border:1px solid #e0e0e0;border-radius:6px;padding:10px 14px;margin:0 0 12px;max-width:700px;">
                <strong>Redirect URI:</strong><br>
                <code style="background:#fff;padding:3px 8px;border:1px solid #ddd;border-radius:4px;display:inline-block;margin-top:6px;word-break:break-all;font-size:13px;"><?php echo esc_html( $gs_url ); ?></code>
                <button type="button" onclick="navigator.clipboard.writeText('<?php echo esc_js( $gs_url ); ?>');this.textContent='Скопировано ✓'" style="margin-left:8px;padding:3px 10px;cursor:pointer;font-size:12px;">Копировать</button>
            </div>
            <table class="form-table" role="presentation" style="margin-top:0;">
                <tr><th style="width:160px;"><label>Mnemonic (Client ID)</label></th>
                    <td><input type="text" name="<?php echo esc_attr( $key ); ?>[gosuslugi_client_id]" value="<?php echo esc_attr( $opts['gosuslugi_client_id'] ?? '' ); ?>" class="regular-text" autocomplete="off" placeholder="Мнемоника вашей системы в ЕСИА"></td></tr>
                <tr><th><label>Client Secret</label></th>
                    <td><input type="password" name="<?php echo esc_attr( $key ); ?>[gosuslugi_client_secret]" value="<?php echo esc_attr( $opts['gosuslugi_client_secret'] ?? '' ); ?>" class="regular-text" autocomplete="new-password">
                    <p class="description">В продуктиве — PKCS#7-подпись с УКЭП.</p></td></tr>
                <tr><th><label>Тестовая среда</label></th>
                    <td><label><input type="checkbox" name="<?php echo esc_attr( $key ); ?>[gosuslugi_test_mode]" value="1" <?php checked( ! empty( $opts['gosuslugi_test_mode'] ) ); ?>> Использовать esia-portal1.test.gosuslugi.ru</label></td></tr>
            </table>

            <?php submit_button( 'Сохранить настройки' ); ?>
        </form>

        <hr style="margin-top:24px;">
        <p style="color:#888;font-size:12px;">WP Authorization RU v<?php echo esc_html( WP_AUTH_RU_VERSION ); ?> | <a href="https://рукодер.рф/" target="_blank">РуКодер</a> · Сергей Солошенко | <a href="https://t.me/RussCoder" target="_blank">Telegram @RussCoder</a></p>
        <?php
    }
}
