# wsServer - Technical Reference

## 1. General Architecture

`wsServer` is a system WebSocket module based on `Flask-SocketIO` and integrated with the application's object model.

The main server-side logic is located in:

- `plugins/wsServer/__init__.py`

Key responsibilities of the module:

- register Socket.IO handlers;
- keep track of connected clients in `connected_clients`;
- broadcast property changes and object HTML updates;
- execute commands coming from the client;
- deliver service events to other parts of the UI;
- act as a transport for custom data streams via `sendData(...)`.

## 2. Connected Client Model

For each `SID`, a record like the following is stored:

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

## 3. Client -> Server Events

### 3.1. `connect`

Client connection event. If the user is not authenticated, the connection is rejected.

### 3.2. `disconnect`

Removes the client from `connected_clients`.

### 3.3. `page`

Updates the current client URL.

```javascript
socket.emit('page', window.location.pathname + window.location.search);
```

### 3.4. `clients`

Request the list of connected clients:

```javascript
socket.emit('clients');
```

### 3.5. `subscribeProperties`

Subscribe to properties in `Object.property` format.

```javascript
socket.emit('subscribeProperties', ['Light1.state', 'Sensor1.temperature']);
```

Notes:

- you can subscribe to everything with `['*']`;
- when subscribing, the server immediately sends the current property value;
- the response arrives as `subscribedProperties`.

### 3.6. `unsubscribeProperties`

```javascript
socket.emit('unsubscribeProperties', ['Light1.state']);
```

### 3.7. `subscribeObjects`

Subscribe to HTML re-rendering of objects:

```javascript
socket.emit('subscribeObjects', ['Light1', 'Thermostat1']);
```

The wildcard form `['*']` is supported.

### 3.8. `unsubscribeObjects`

```javascript
socket.emit('unsubscribeObjects', ['Light1']);
```

### 3.9. `subscribeMethods`

Subscribe to method execution results in `Object.method` format.

```javascript
socket.emit('subscribeMethods', ['Light1.toggle', 'Sensor1.refresh']);
```

Notes:

- you can subscribe to everything with `['*']`;
- when subscribing, the server immediately sends the current method state;
- the response arrives as `subscribedMethods`.

### 3.10. `unsubscribeMethods`

```javascript
socket.emit('unsubscribeMethods', ['Light1.toggle']);
```

### 3.11. `subscribeActions`

Subscribe to service actions:

```javascript
socket.emit('subscribeActions', ['say', 'notify', 'playsound']);
```

Notes:

- `executedMethod` is no longer subscribed through `subscribeActions`;
- use `subscribeMethods` instead;
- for backward compatibility, `subscribeActions` with `executedMethod` is mapped to `subscribeMethods(['*'])`.

### 3.12. `unsubscribeActions`

```javascript
socket.emit('unsubscribeActions', ['notify']);
```

### 3.13. `subscribeData`

Subscribe to arbitrary data types that the server sends via `sendData(...)`:

```javascript
socket.emit('subscribeData', ['zigbee', 'telemetry']);
```

You can subscribe to everything:

```javascript
socket.emit('subscribeData', ['*']);
```

### 3.14. `unsubscribeData`

```javascript
socket.emit('unsubscribeData', ['telemetry']);
```

### 3.13. `setProperty`

Set an object property value:

```javascript
socket.emit('setProperty', 'Light1.state', true, 'WS');
```

The response comes back as `propertyChanged`.

Successful response format:

```json
{
  "success": true,
  "property": "Light1.state",
  "value": true
}
```

Error response format:

```json
{
  "success": false,
  "property": "Light1.state",
  "error": "..."
}
```

Notes:

- the server expects the `Object.property` format;
- validation and permission errors are returned as text;
- the default source is `WS`.

### 3.14. `callMethod`

Call an object method:

```javascript
socket.emit('callMethod', 'Light1.toggle', 'WS', false);
```

If a result is needed:

```javascript
socket.emit('callMethod', 'Calc1.getStatus', 'WS', true);
```

Then the response is sent as `resultCallMethod`.

### 3.15. `lsp`

Service channel for LSP actions from the code editor.

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

System restart command. It is executed only for users with the `admin` role.

## 4. Server -> Client Events

### 4.1. `clients`

Reference payload for connected clients. Each record contains:

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

Sent when a property changes.

Example payload:

```json
{
  "property": "Light1.state",
  "value": true,
  "source": "Rule",
  "changed": "2026-03-26 12:30:00+03:00"
}
```

### 4.3. `changeObject`

Sends fresh object HTML:

```json
{
  "object": "Light1",
  "value": "<div>...</div>"
}
```

### 4.4. `executedMethod`

Event about an executed object method.

The payload contains:

- `method`;
- `source`;
- `executed`;
- `exec_params`;
- `exec_result`;
- `exec_time`.

To receive this event, the client must subscribe to the method through `subscribeMethods`.

Example:

```javascript
socket.emit('subscribeMethods', ['Light1.toggle']);
```

### 4.5. `say`

System text message:

```json
{
  "message": "Heating started",
  "level": 0,
  "args": {
    "source": "Boiler",
    "title": "Notification"
  }
}
```

### 4.6. `notify`

Service notification for the UI. It is used, for example, to synchronize the notification center.

### 4.7. `playsound`

Command to play a sound:

```json
{
  "file_url": "/sound/alert.mp3",
  "level": 0,
  "args": null
}
```

### 4.8. `propertyChanged`

Response to `setProperty`. Used to confirm a successful update or return an error message.

### 4.9. `resultCallMethod`

Response to `callMethod(..., sendResult=true)`.

### 4.10. `lsp`

Response to an LSP request. The payload includes `requestId` so the client can match the response to the request.

## 5. Server-Side Module Methods

### 5.1. `say(message, level=0, args=None)`

Sends the `say` event only to clients that subscribed to `say`.

```python
plugin.say("System started")
```

### 5.2. `notify(data: dict)`

Sends the `notify` event to subscribed clients.

### 5.3. `playSound(file_name, level=0, args=None)`

Caches the file path and sends the `playsound` event to the client.

Notes:

- the file must exist on the server;
- the client receives a URL in the form `/sound/<filename>`;
- file download is protected by the `handle_user_required` decorator.

### 5.4. `changeProperty(obj, prop, value)`

Broadcasts:

- `changeProperty` to property subscribers;
- `changeObject` to object subscribers.

This method:

- takes the user's timezone into account;
- renders object HTML only when there are `subscribeObjects` subscribers;
- sends `changeProperty` only when there are `subscribeProperties` subscribers;
- de-duplicates `changeProperty` by `(value, source, changed)` state per `Object.property`;
- supports per-property server-side debounce (configurable in module settings);
- de-duplicates `changeObject` by comparing rendered HTML with the last sent version;
- supports per-object server-side debounce (configurable in module settings);
- does not allow an object render failure to break `changeProperty` delivery.

Debounce-related config keys:

- `object_render_debounce_enabled` (bool, default `true`);
- `object_render_debounce_ms` (int, default `120`, range `0..5000`).
- `property_change_debounce_enabled` (bool, default `false`);
- `property_change_debounce_ms` (int, default `80`, range `0..5000`).

### 5.5. `executedMethod(obj, method)`

Broadcasts `executedMethod` to clients subscribed to that method (or `*`).

### 5.6. `sendData(typeData, data)`

Broadcasts an arbitrary payload to clients subscribed to `typeData`.

```python
plugin.sendData("telemetry", {"temp": 23.5, "ts": some_datetime})
```

Notes:

- if there are no subscribers, the method still returns success without sending anything;
- `datetime` values are automatically converted to the user's local time;
- `date` values are converted to ISO strings;
- the original payload is not mutated.

### 5.7. `sendCommand(command, data, client_id=None)`

Allows sending an arbitrary Socket.IO event:

```python
plugin.sendCommand("customEvent", {"ok": True})
```

If `client_id` is provided, the command is sent to only one client.

### 5.8. `sendClientsInfo(room=None)`

Sends the `connected_clients` state either to one client or to all clients.

## 6. Internal Implementation Notes

- the client list is stored in process memory in `connected_clients`;
- traffic statistics are approximate and based on string size of sent and received data;
- `changeObject` depends on successful `render()` execution for the object;
- `restart_system` is restricted to the `admin` role;
- after reconnecting, the frontend may reload the page to restore state;
- `socketio.emit` is wrapped to count sent bytes;
- object updates on the client use `morphdom` to update the DOM without replacing the whole container.
