<?php
/**
 * Выполняется WordPress при удалении плагина.
 *
 * Удаляет: настройки, OAuth user_meta, журнал, transient'ы.
 * НЕ удаляет: пользователей, заказы, посты.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

// ── 1. Настройки и маркеры ────────────────────────────────────────────────────
delete_option( 'wp_authorization_ru_settings' );
delete_option( 'wp_auth_ru_updater_cache_reset_v1' );

// ── 2. Журнал событий ─────────────────────────────────────────────────────────
delete_option( 'wp_auth_ru_log' );

// ── 3. Transient'ы (кэш GitHub API) ──────────────────────────────────────────
delete_transient( 'wp_auth_ru_github_update' );

// ── 4. OAuth user_meta всех провайдеров ──────────────────────────────────────
$meta_keys = array(
    'wp_auth_ru_yandex_oauth_id',
    'wp_auth_ru_mailru_oauth_id',
    'wp_auth_ru_vk_oauth_id',
    'wp_auth_ru_rambler_oauth_id',
    'wp_auth_ru_max_oauth_id',
    'wp_auth_ru_gosuslugi_oid',
    'wp_auth_ru_provider',
    'gosuslugi_patronymic',
);
foreach ( $meta_keys as $meta_key ) {
    delete_metadata( 'user', 0, $meta_key, '', true );
}

// ── 5. OAuth state transient'ы ────────────────────────────────────────────────
global $wpdb;
$wpdb->query(
    "DELETE FROM {$wpdb->options}
     WHERE option_name LIKE '_transient_wp_auth_ru_%'
        OR option_name LIKE '_transient_timeout_wp_auth_ru_%'"
);

// ── 6. Multisite ──────────────────────────────────────────────────────────────
if ( is_multisite() ) {
    $sites = get_sites( array( 'number' => 0, 'fields' => 'ids' ) );
    foreach ( $sites as $site_id ) {
        switch_to_blog( $site_id );
        delete_option( 'wp_authorization_ru_settings' );
        delete_option( 'wp_auth_ru_updater_cache_reset_v1' );
        delete_option( 'wp_auth_ru_log' );
        delete_transient( 'wp_auth_ru_github_update' );
        $wpdb->query(
            "DELETE FROM {$wpdb->options}
             WHERE option_name LIKE '_transient_wp_auth_ru_%'
                OR option_name LIKE '_transient_timeout_wp_auth_ru_%'"
        );
        restore_current_blog();
    }
}
