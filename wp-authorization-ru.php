<?php
/**
 * Plugin Name:       WP Authorization RU
 * Plugin URI:        https://рукодер.рф/
 * Description:       Авторизация через Яндекс ID, Mail.ru, ВКонтакте, Rambler, MAX и Госуслуги (ЕСИА). Блокировка иностранных сервисов (КоАП РФ). Журнал событий. Автообновление с GitHub.
 * Version:           1.0.3
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
 * GitHub:    https://github.com/RuCoder-sudo/wp-authorization-ru
 * Email:     rucoder.rf@yandex.ru
 * Telegram:  @RussCoder
 * Сайт:      https://рукодер.рф
 * -----------------------------------------------------------------------
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'WP_AUTH_RU_VERSION',         '1.0.3' );
define( 'WP_AUTH_RU_PLUGIN_FILE',     __FILE__ );
define( 'WP_AUTH_RU_PLUGIN_DIR',      plugin_dir_path( __FILE__ ) );
define( 'WP_AUTH_RU_PLUGIN_URL',      plugin_dir_url( __FILE__ ) );
define( 'WP_AUTH_RU_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
define( 'WP_AUTH_RU_OPTIONS_KEY',     'wp_authorization_ru_settings' );

require_once WP_AUTH_RU_PLUGIN_DIR . 'includes/class-wp-auth-ru-logger.php';
require_once WP_AUTH_RU_PLUGIN_DIR . 'includes/class-wp-auth-ru-updater.php';
require_once WP_AUTH_RU_PLUGIN_DIR . 'includes/class-wp-auth-ru-compliance.php';
require_once WP_AUTH_RU_PLUGIN_DIR . 'includes/class-wp-auth-ru-admin.php';
require_once WP_AUTH_RU_PLUGIN_DIR . 'includes/class-wp-auth-ru-yandex.php';
require_once WP_AUTH_RU_PLUGIN_DIR . 'includes/class-wp-auth-ru-mailru.php';
require_once WP_AUTH_RU_PLUGIN_DIR . 'includes/class-wp-auth-ru-vk.php';
require_once WP_AUTH_RU_PLUGIN_DIR . 'includes/class-wp-auth-ru-rambler.php';
require_once WP_AUTH_RU_PLUGIN_DIR . 'includes/class-wp-auth-ru-max.php';
require_once WP_AUTH_RU_PLUGIN_DIR . 'includes/class-wp-auth-ru-gosuslugi.php';

function wp_authorization_ru_init() {
    new WP_Auth_Ru_Updater( WP_AUTH_RU_PLUGIN_FILE, WP_AUTH_RU_VERSION );
    WP_Auth_Ru_Compliance::instance();
    WP_Auth_Ru_Admin::instance();
    WP_Auth_Ru_Yandex::instance();
    WP_Auth_Ru_Mailru::instance();
    WP_Auth_Ru_VK::instance();
    WP_Auth_Ru_Rambler::instance();
    WP_Auth_Ru_Max::instance();
    WP_Auth_Ru_Gosuslugi::instance();
}
add_action( 'plugins_loaded', 'wp_authorization_ru_init' );

// WooCommerce HPOS совместимость
add_action( 'before_woocommerce_init', function () {
    if ( class_exists( '\Automattic\WooCommerce\Utilities\FeaturesUtil' ) &&
         method_exists( '\Automattic\WooCommerce\Utilities\FeaturesUtil', 'declare_compatibility' ) ) {
        \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility(
            'custom_order_tables', WP_AUTH_RU_PLUGIN_FILE, true
        );
    }
} );
