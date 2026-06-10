# Авторизация WordPress через российские сервисы

<div align="center">

**WP Authorization RU** — плагин для WordPress, который добавляет вход и регистрацию через 6 российских OAuth-сервисов. Автообновление с GitHub, полная поддержка WooCommerce.

![Version](https://img.shields.io/badge/version-1.0.3-blue?style=flat-square)
![WordPress](https://img.shields.io/badge/WordPress-5.8%2B-21759b?style=flat-square&logo=wordpress)
![WooCommerce](https://img.shields.io/badge/WooCommerce-5.0%2B-96588a?style=flat-square)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-777bb4?style=flat-square&logo=php)
![License](https://img.shields.io/badge/license-GPLv2-green?style=flat-square)
![GitHub release](https://img.shields.io/github/v/release/RuCoder-sudo/wp-authorization-ru?style=flat-square)

[Получить плагин](https://рукодер.рф) · [Установка](#установка) · [Настройка](#настройка) · [Автообновление](#автообновление-с-github) · [Поддержка](#поддержка)

</div>

---

## О плагине

**WP Authorization RU** добавляет кнопки входа через 6 российских сервисов на все ключевые страницы вашего WordPress-сайта. При выходе новых версий плагин обновляется автоматически прямо из GitHub — без посещения WordPress.org.

| Провайдер | Протокол | Что нужно |
|---|---|---|
| 🔵 **Яндекс ID** | OAuth 2.0 | Client ID + Secret от oauth.yandex.ru |
| 🔵 **Mail.ru** | OAuth 2.0 | Client ID + Secret от o2.mail.ru |
| 🔵 **ВКонтакте** | OAuth 2.0 | Client ID + Secret от dev.vk.com |
| 🔵 **Rambler** | OAuth 2.0 / OpenID | Client ID + Secret от id.rambler.ru |
| 🔵 **MAX Мессенджер** | Mini App HMAC-SHA256 | Bot Token + настройка Mini App |
| 🔵 **Госуслуги (ЕСИА)** | OAuth 2.0 + УКЭП | Юр. лицо, mnemonic, УКЭП |

---

## Возможности

### Где появляются кнопки

| Место | Яндекс | Mail.ru | VK | Rambler | MAX | Госуслуги |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Страница входа WordPress | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Страница регистрации WordPress | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Мой аккаунт WooCommerce — вход | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Мой аккаунт WooCommerce — регистрация | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Оформление заказа WooCommerce | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Безопасность

| Механизм | Описание |
|---|---|
| CSRF-защита | state-параметр (WordPress nonce + transient, 10 минут) |
| Callback URL | WordPress REST API — чистый URL без query-параметров |
| Санитизация | Все входные данные через функции WordPress |
| Редирект | Только на страницы того же сайта |
| MAX подпись | HMAC-SHA256 + проверка auth_date (не старше 1 часа) |

---

## Автообновление с GitHub

Плагин проверяет новые релизы на GitHub каждые **12 часов**.

Как это работает:
1. WordPress запрашивает `api.github.com/repos/RuCoder-sudo/wp-authorization-ru/releases/latest`
2. Если тег новее текущей версии — появляется стандартное уведомление «Доступно обновление»
3. Администратор нажимает «Обновить» — WordPress скачивает ZIP из GitHub и устанавливает
4. После установки папка плагина автоматически переименовывается, плагин реактивируется

**Чтобы выпустить обновление** — создайте новый GitHub Release с тегом `v1.0.2` (или выше). WordPress на всех сайтах увидит его при следующей проверке.

---

## Требования

- WordPress 5.8 или выше
- PHP 7.4 или выше (протестировано на PHP 8.0–8.3)
- WordPress REST API должен быть доступен
- Ключи от нужного провайдера

---

## Установка

### Способ 1: через панель WordPress

1. Скачайте ZIP-архив плагина с [GitHub Releases](https://github.com/RuCoder-sudo/wp-authorization-ru/releases)
2. Перейдите в **Плагины → Добавить новый → Загрузить плагин**
3. Выберите ZIP-файл и нажмите **Установить**
4. Нажмите **Активировать плагин**

### Способ 2: через FTP / SSH

```bash
git clone https://github.com/RuCoder-sudo/wp-authorization-ru.git
```
Загрузите папку в `/wp-content/plugins/` и активируйте в панели WordPress.

---

## Настройка

Перейдите в **Настройки → Авторизация RU** и настройте нужные провайдеры.

### 🔵 Яндекс ID
1. [oauth.yandex.ru](https://oauth.yandex.ru/) → «Зарегистрировать приложение» → Тип: **Веб-сервисы**
2. Права: `login:info`, `login:email`
3. Redirect URI: скопируйте из настроек плагина (`/wp-json/wp-auth-ru/v1/yandex/callback`)

### 🔵 Mail.ru
1. [o2.mail.ru/app](https://o2.mail.ru/app/) → «Добавить приложение» → Тип: **Сайт**
2. Redirect URI: `/wp-json/wp-auth-ru/v1/mailru/callback`

### 🔵 ВКонтакте
1. [dev.vk.com](https://dev.vk.com/) → «Мои приложения» → «Создать» → Тип: **Веб-сайт**
2. В настройках приложения включите доступ к **email**
3. Redirect URI: `/wp-json/wp-auth-ru/v1/vk/callback`

### 🔵 Rambler
1. [id.rambler.ru/apps](https://id.rambler.ru/apps) → «Добавить приложение» → Тип: **Веб-сайт**
2. Redirect URI: `/wp-json/wp-auth-ru/v1/rambler/callback`

### 🔵 MAX Мессенджер

MAX использует Mini App — не стандартный OAuth:

1. [max.ru/partner](https://max.ru/partner) → Чат-боты → ваш бот → «Интеграция» → получите **Bot Token**
2. В разделе «Мини-приложение» укажите URL вашего сайта
3. В настройках плагина введите Bot Token и @username бота

> Вход происходит автоматически, когда пользователь открывает сайт через бота MAX.

### 🏛️ Госуслуги (ЕСИА)

> ⚠️ Только для юридических лиц (ИП, ООО). Требуется УКЭП.

1. Зарегистрируйте систему на [esia.gosuslugi.ru/console/tech](https://esia.gosuslugi.ru/console/tech/)
2. Получите **mnemonic** (Client ID)
3. Для тестирования: включите «Тестовая среда» в настройках плагина
4. Redirect URI: `/wp-json/wp-auth-ru/v1/gosuslugi/callback`

> В продуктивной среде запрос токена должен быть подписан PKCS#7 с УКЭП организации.

---

## Changelog

### [1.0.1] — 2026-06-10

**Добавлено:**
- Автообновление с GitHub — обновления устанавливаются одним кликом прямо из панели WordPress
- Авторизация через ВКонтакте (VK OAuth 2.0)
- Авторизация через Rambler ID (OpenID Connect / OAuth 2.0)
- Авторизация через MAX мессенджер (Mini App, HMAC-SHA256 initData)
- Авторизация через Госуслуги / ЕСИА (OAuth 2.0, тестовая среда)
- `uninstall.php` — очистка настроек и user_meta при удалении плагина
- `CHANGELOG.md` — история изменений

**Изменено:**
- Страница настроек: 6 провайдеров с инструкциями и кнопками копирования Redirect URI
- Версия плагина: 1.0.1

### [1.0.0] — 2026-06-07

- Первый релиз. Яндекс ID + Mail.ru. Кнопки на страницах WordPress и WooCommerce.

---

## Поддержка

| Канал | Контакт |
|---|---|
| Telegram | [@RussCoder](https://t.me/RussCoder) |
| Email | [rucoder.rf@yandex.ru](mailto:rucoder.rf@yandex.ru) |
| Сайт | [рукодер.рф](https://рукодер.рф) |
| GitHub Issues | [github.com/RuCoder-sudo/wp-authorization-ru/issues](https://github.com/RuCoder-sudo/wp-authorization-ru/issues) |

---

## Особые условия лицензирования для социально значимых проектов

Для организаций в сфере социального обслуживания, благотворительности, образования, здравоохранения, культуры и спорта (ФЗ № 7-ФЗ, № 135-ФЗ) — лицензия предоставляется бесплатно по письменному запросу.

Контакт: [Telegram @RussCoder](https://t.me/RussCoder) / [rucoder.rf@yandex.ru](mailto:rucoder.rf@yandex.ru)

---

## Лицензия

[GPL-2.0+](https://www.gnu.org/licenses/gpl-2.0.html)

<div align="center">

<img src="https://komarev.com/ghpvc/?username=RuCoder-sudo&style=flat-square&color=blue" alt="GitHub Profile Views" />

---

Разработано — <a href="https://рукодер.рф">РуКодер</a> · Сергей Солошенко

</div>
