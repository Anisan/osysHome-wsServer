# wsServer - Техническая документация

## 1. Общая архитектура

`wsServer` это системный модуль WebSocket на базе `Flask-SocketIO`, интегрированный с объектной моделью приложения.

Основная серверная логика находится в:

- `plugins/wsServer/__init__.py`

Ключевые обязанности модуля:

- регистрация Socket.IO-обработчиков;
- хранение списка подключённых клиентов в `connected_clients`;
- рассылка изменений свойств и HTML объектов;
- выполнение команд клиента;
- передача служебных событий другим частям интерфейса;
- транспорт для пользовательских потоков данных через `sendData(...)`.

## 2. Модель подключённого клиента

Для каждого `SID` хранится запись вида:

```json
{
  "username": "user",
  "ip": "127.0.0.1",
  "connected": "2026-03-26 12:00:00",
  "transport": "websocket",
  "page": "/admin/wsServer",
  "stats": {
    "recvBytes": 0,
    "sentBytes": 0
  },
  "subsProperties": [],
  "subsObjects": [],
  "subsData": [],
  "subsActions": []
}
```

## 3. События клиента -> сервер

### 3.1. `connect`

Подключение клиента. Если пользователь не аутентифицирован, соединение отклоняется.

### 3.2. `disconnect`

Удаляет клиента из `connected_clients`.

### 3.3. `page`

Обновляет текущий URL клиента.

```javascript
socket.emit('page', window.location.pathname + window.location.search);
```

### 3.4. `clients`

Запросить список подключённых клиентов:

```javascript
socket.emit('clients');
```

### 3.5. `subscribeProperties`

Подписка на свойства формата `Object.property`.

```javascript
socket.emit('subscribeProperties', ['Light1.state', 'Sensor1.temperature']);
```

Особенности:

- можно подписаться на всё через `['*']`;
- при подписке сервер сразу отправляет текущее значение свойства;
- ответ приходит событием `subscribedProperties`.

### 3.6. `unsubscribeProperties`

```javascript
socket.emit('unsubscribeProperties', ['Light1.state']);
```

### 3.7. `subscribeObjects`

Подписка на HTML-перерисовку объектов:

```javascript
socket.emit('subscribeObjects', ['Light1', 'Thermostat1']);
```

Поддерживается общий шаблон `['*']`.

### 3.8. `unsubscribeObjects`

```javascript
socket.emit('unsubscribeObjects', ['Light1']);
```

### 3.9. `subscribeActions`

Подписка на действия и служебные события:

```javascript
socket.emit('subscribeActions', ['say', 'notify', 'playsound', 'executedMethod']);
```

### 3.10. `unsubscribeActions`

```javascript
socket.emit('unsubscribeActions', ['notify']);
```

### 3.11. `subscribeData`

Подписка на произвольные типы данных, которые сервер отправляет через `sendData(...)`:

```javascript
socket.emit('subscribeData', ['zigbee', 'telemetry']);
```

Можно подписаться на всё:

```javascript
socket.emit('subscribeData', ['*']);
```

### 3.12. `unsubscribeData`

```javascript
socket.emit('unsubscribeData', ['telemetry']);
```

### 3.13. `setProperty`

Установить значение свойства объекта:

```javascript
socket.emit('setProperty', 'Light1.state', true, 'WS');
```

Ответ приходит событием `propertyChanged`.

Формат успешного ответа:

```json
{
  "success": true,
  "property": "Light1.state",
  "value": true
}
```

Формат ответа с ошибкой:

```json
{
  "success": false,
  "property": "Light1.state",
  "error": "..."
}
```

Особенности:

- сервер ожидает формат имени `Object.property`;
- ошибки валидации и прав доступа передаются в текстовом виде;
- источник изменения по умолчанию равен `WS`.

### 3.14. `callMethod`

Вызов метода объекта:

```javascript
socket.emit('callMethod', 'Light1.toggle', 'WS', false);
```

Если нужен результат:

```javascript
socket.emit('callMethod', 'Calc1.getStatus', 'WS', true);
```

Тогда ответ придёт событием `resultCallMethod`.

### 3.15. `lsp`

Служебный канал для вызова LSP-действий из редактора кода.

```javascript
socket.emit('lsp', {
  requestId: 'req-1',
  action: 'hover',
  code: 'x = 1',
  line: 1,
  column: 1,
  timeout: 1.5,
  object_name: 'MyObject',
  module_name: 'Objects'
});
```

### 3.16. `restart_system`

Команда перезапуска системы. Выполняется только для пользователей с ролью `admin`.

## 4. События сервер -> клиент

### 4.1. `clients`

Справочник подключённых клиентов. Каждая запись содержит:

- `username`;
- `ip`;
- `connected`;
- `transport`;
- `page`;
- `stats.recvBytes`;
- `stats.sentBytes`;
- `subsProperties`;
- `subsObjects`;
- `subsData`;
- `subsActions`.

### 4.2. `changeProperty`

Отправляется при изменении свойства.

Пример payload:

```json
{
  "property": "Light1.state",
  "value": true,
  "source": "Rule",
  "changed": "2026-03-26 12:30:00+03:00"
}
```

### 4.3. `changeObject`

Отправляет новый HTML объекта:

```json
{
  "object": "Light1",
  "value": "<div>...</div>"
}
```

### 4.4. `executedMethod`

Событие о выполнении метода объекта.

Payload содержит:

- `method`;
- `source`;
- `executed`;
- `exec_params`;
- `exec_result`;
- `exec_time`.

Чтобы получать событие, клиент должен подписаться на `executedMethod` через `subscribeActions`.

### 4.5. `say`

Системное текстовое сообщение:

```json
{
  "message": "Heating started",
  "level": 0,
  "args": {
    "source": "Boiler",
    "title": "Уведомление"
  }
}
```

### 4.6. `notify`

Служебное уведомление для интерфейса. Используется, например, для синхронизации центра уведомлений.

### 4.7. `playsound`

Команда воспроизвести звук:

```json
{
  "file_url": "/sound/alert.mp3",
  "level": 0,
  "args": null
}
```

### 4.8. `propertyChanged`

Ответ на `setProperty`. Используется для подтверждения успешного изменения или передачи текста ошибки.

### 4.9. `resultCallMethod`

Ответ на `callMethod(..., sendResult=true)`.

### 4.10. `lsp`

Ответ на LSP-запрос. В payload возвращается `requestId`, чтобы клиент смог связать ответ с запросом.

## 5. Серверные методы модуля

### 5.1. `say(message, level=0, args=None)`

Отправляет событие `say` только тем клиентам, которые подписались на `say`.

```python
plugin.say("Система запущена")
```

### 5.2. `notify(data: dict)`

Отправляет событие `notify` подписанным клиентам.

### 5.3. `playSound(file_name, level=0, args=None)`

Кэширует путь к файлу и отправляет клиенту событие `playsound`.

Особенности:

- файл должен быть доступен на сервере;
- клиент получает URL вида `/sound/<filename>`;
- скачивание файла защищено декоратором `handle_user_required`.

### 5.4. `changeProperty(obj, prop, value)`

Рассылает:

- `changeProperty` подписчикам свойств;
- `changeObject` подписчикам объектов.

Метод:

- учитывает часовой пояс пользователя;
- рендерит HTML объекта только при наличии подписчиков `subscribeObjects`;
- отправляет `changeProperty` только при наличии подписчиков `subscribeProperties`;
- делает дедупликацию `changeProperty` по состоянию `(value, source, changed)` для `Object.property`;
- поддерживает серверный debounce по свойствам (настраивается в параметрах модуля);
- делает дедупликацию `changeObject` по сравнению с последней отправленной версией HTML;
- поддерживает серверный debounce по объекту (настраивается в параметрах модуля);
- не даёт ошибке рендера объекта сломать отправку `changeProperty`.

Ключи конфигурации debounce:

- `object_render_debounce_enabled` (bool, по умолчанию `true`);
- `object_render_debounce_ms` (int, по умолчанию `120`, диапазон `0..5000`).
- `property_change_debounce_enabled` (bool, по умолчанию `false`);
- `property_change_debounce_ms` (int, по умолчанию `80`, диапазон `0..5000`).

### 5.5. `executedMethod(obj, method)`

Рассылает `executedMethod` клиентам, подписанным на соответствующее действие.

### 5.6. `sendData(typeData, data)`

Рассылает произвольный payload клиентам, подписанным на `typeData`.

```python
plugin.sendData("telemetry", {"temp": 23.5, "ts": some_datetime})
```

Особенности:

- если подписчиков нет, метод завершится успешно без рассылки;
- `datetime` автоматически переводится в локальное время пользователя;
- `date` переводится в `ISO`-строку;
- исходный payload не мутируется.

### 5.7. `sendCommand(command, data, client_id=None)`

Позволяет отправить произвольное Socket.IO-событие:

```python
plugin.sendCommand("customEvent", {"ok": True})
```

Если указан `client_id`, команда уйдёт только одному клиенту.

### 5.8. `sendClientsInfo(room=None)`

Рассылает состояние `connected_clients` одному клиенту или всем сразу.

## 6. Внутренние особенности реализации

- список клиентов хранится в памяти процесса в `connected_clients`;
- статистика трафика считается приблизительно, по строковому размеру отправляемых и принимаемых данных;
- событие `changeObject` зависит от успешного `render()` объекта;
- событие `restart_system` ограничено ролью `admin`;
- при повторном подключении клиента фронтенд может перезагрузить страницу для восстановления состояния;
- `socketio.emit` переопределён обёрткой для подсчёта отправленных байт;
- при обновлении объекта на клиенте используется `morphdom`, чтобы обновлять DOM без полной замены контейнера.
