<?php
/**
 * Журнал событий авторизации WP Authorization RU.
 *
 * Хранит последние 200 записей в wp_options (без autoload).
 * Каждая запись содержит: время, уровень, провайдер, сообщение и необязательный контекст.
 *
 * Уровни:  INFO · SUCCESS · WARNING · ERROR
 *
 * Использование в провайдерах:
 *   WP_Auth_Ru_Logger::log( 'INFO',    'yandex', 'OAuth flow начат' );
 *   WP_Auth_Ru_Logger::log( 'SUCCESS', 'yandex', 'Вход: #5 i***@ya.ru' );
 *   WP_Auth_Ru_Logger::log( 'ERROR',   'yandex', 'Ошибка токена: ...' );
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WP_Auth_Ru_Logger {

    const OPTION_KEY  = 'wp_auth_ru_log';
    const MAX_ENTRIES = 200;

    const INFO    = 'INFO';
    const SUCCESS = 'SUCCESS';
    const WARNING = 'WARNING';
    const ERROR   = 'ERROR';

    // ─── Запись события ──────────────────────────────────────────────────────

    public static function log( $level, $provider, $message, $context = array() ) {
        $entry = array(
            'time'     => current_time( 'Y-m-d H:i:s' ),
            'ts'       => time(),
            'level'    => strtoupper( $level ),
            'provider' => strtolower( $provider ),
            'msg'      => (string) $message,
        );

        if ( ! empty( $context ) ) {
            $entry['ctx'] = $context;
        }

        $logs = get_option( self::OPTION_KEY, array() );
        if ( ! is_array( $logs ) ) {
            $logs = array();
        }

        // Новые записи — сверху
        array_unshift( $logs, $entry );

        if ( count( $logs ) > self::MAX_ENTRIES ) {
            $logs = array_slice( $logs, 0, self::MAX_ENTRIES );
        }

        // false = не добавлять в autoload (не грузить на каждой странице)
        update_option( self::OPTION_KEY, $logs, false );
    }

    // ─── Получить все записи ─────────────────────────────────────────────────

    public static function get_logs() {
        $logs = get_option( self::OPTION_KEY, array() );
        return is_array( $logs ) ? $logs : array();
    }

    // ─── Очистить журнал ─────────────────────────────────────────────────────

    public static function clear_logs() {
        update_option( self::OPTION_KEY, array(), false );
    }

    // ─── Статистика ──────────────────────────────────────────────────────────

    public static function get_stats() {
        $logs  = self::get_logs();
        $stats = array(
            'total'     => count( $logs ),
            'success'   => 0,
            'error'     => 0,
            'info'      => 0,
            'warning'   => 0,
            'providers' => array(),
        );

        $provider_labels = array(
            'yandex'     => 'Яндекс',
            'mailru'     => 'Mail.ru',
            'vk'         => 'ВКонтакте',
            'rambler'    => 'Rambler',
            'max'        => 'MAX',
            'gosuslugi'  => 'Госуслуги',
            'compliance' => 'Блокировка',
            'system'     => 'Система',
        );

        foreach ( $logs as $entry ) {
            $level = strtolower( $entry['level'] ?? '' );
            if ( isset( $stats[ $level ] ) ) {
                $stats[ $level ]++;
            }

            $p = $entry['provider'] ?? 'other';
            if ( ! isset( $stats['providers'][ $p ] ) ) {
                $stats['providers'][ $p ] = array(
                    'label'   => $provider_labels[ $p ] ?? ucfirst( $p ),
                    'total'   => 0,
                    'success' => 0,
                    'error'   => 0,
                );
            }
            $stats['providers'][ $p ]['total']++;
            if ( $level === 'success' ) $stats['providers'][ $p ]['success']++;
            if ( $level === 'error'   ) $stats['providers'][ $p ]['error']++;
        }

        return $stats;
    }

    // ─── Маскировка email (i***@domain.ru) ───────────────────────────────────

    public static function mask_email( $email ) {
        if ( ! $email ) return '';
        $parts = explode( '@', $email, 2 );
        if ( count( $parts ) !== 2 ) {
            return substr( $email, 0, 2 ) . '***';
        }
        return substr( $parts[0], 0, 1 ) . '***@' . $parts[1];
    }
}
