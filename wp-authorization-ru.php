<?php
/**
 * Plugin Name:       WP Authorization RU
 * Plugin URI:        https://рукодер.рф/
 * Description:       Авторизация и регистрация через российские сервисы: Яндекс ID и Mail.ru OAuth. Поддержка стандартных форм WordPress и WooCommerce (включая оформление заказа).
 * Version:           1.0.0
 * Author:            Сергей Солошенко (RuCoder)
 * Author URI:        https://рукодер.рф/
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-authorization-ru
 * Domain Path:       /languages
 * Requires at least: 5.8
 * Tested up to:      6.7
 * Requires PHP:      7.4
 * WC requires at least: 5.0
 * WC tested up to:   9.9
 *
 * -----------------------------------------------------------------------
 * Разработчик:        Сергей Солошенко | РуКодер
 * Телефон / WhatsApp: +7 (985) 985-53-97
 * Email:              support@рукодер.рф
 * Telegram:           @RussCoder
 * Портфолио:          https://рукодер.рф
 * GitHub:             https://github.com/RuCoder-sudo
 * -----------------------------------------------------------------------
 *
 * Возможности плагина:
 *  - Кнопки «Войти через Яндекс» и «Войти через Mail.ru» на стандартных
 *    страницах входа и регистрации WordPress.
 *  - Кнопки на страницах входа и регистрации WooCommerce (Мой аккаунт).
 *  - Баннер быстрой авторизации на странице оформления заказа WooCommerce.
 *  - Автоматическое создание учётной записи при первом входе.
 *  - Хранение OAuth ID провайдера в user_meta для распознавания повторных входов.
 *  - Настройки: Client ID и Client Secret для каждого провайдера.
 * -----------------------------------------------------------------------
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'WP_AUTH_RU_VERSION',       '1.0.0' );
define( 'WP_AUTH_RU_PLUGIN_FILE',   __FILE__ );
define( 'WP_AUTH_RU_PLUGIN_DIR',    plugin_dir_path( __FILE__ ) );
define( 'WP_AUTH_RU_PLUGIN_URL',    plugin_dir_url( __FILE__ ) );
define( 'WP_AUTH_RU_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
define( 'WP_AUTH_RU_OPTIONS_KEY',   'wp_authorization_ru_settings' );

require_once WP_AUTH_RU_PLUGIN_DIR . 'includes/class-wp-auth-ru-admin.php';
require_once WP_AUTH_RU_PLUGIN_DIR . 'includes/class-wp-auth-ru-yandex.php';
require_once WP_AUTH_RU_PLUGIN_DIR . 'includes/class-wp-auth-ru-mailru.php';

function wp_authorization_ru_init() {
    WP_Auth_Ru_Admin::instance();
    WP_Auth_Ru_Yandex::instance();
    WP_Auth_Ru_Mailru::instance();
}
add_action( 'plugins_loaded', 'wp_authorization_ru_init' );

// WooCommerce HPOS compatibility declaration
add_action( 'before_woocommerce_init', function () {
    if ( class_exists( '\Automattic\WooCommerce\Utilities\FeaturesUtil' ) ) {
        if ( method_exists( '\Automattic\WooCommerce\Utilities\FeaturesUtil', 'declare_compatibility' ) ) {
            \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility(
                'custom_order_tables',
                WP_AUTH_RU_PLUGIN_FILE,
                true
            );
        }
    }
} );
