# wsServer - User Guide

## 1. Module Purpose

`wsServer` is a system module that starts a WebSocket connection based on `Flask-SocketIO` and enables real-time data exchange between the application and the browser.

The module is intended for cases where a normal page refresh is not enough:

- instantly display object property changes;
- re-render object HTML without reloading the page;
- send notifications and messages to the user;
- play sounds in the browser;
- call object methods from the client;
- deliver arbitrary data from server modules to the web interface;
- monitor active connections and their subscriptions.

## 2. What the User Gets

After the page loads, the frontend connects to the Socket.IO server and automatically:

- subscribes to the service events `say`, `playsound`, and `notify`;
- scans the page for property and object bindings;
- subscribes to the required properties and objects;
- sends the current page URL to the server.

Because of this, the user sees updates immediately without manually refreshing the browser.

## 3. Requirements and Conditions

- the user must be authenticated;
- the connection is created through the shared client script `app/templates/includes/websockets.html`;
- the module works via `Socket.IO`, so the transport may be either `websocket` or a long-polling fallback;
- for correct time rendering, the user's timezone is used if it is set in `<username>.timezone`.

If the user is not authenticated, the connection is rejected.

## 4. Administrative Interface

The admin page is available at:

```text
/admin/wsServer
```

The module includes three tabs.

### 4.1. Clients

Shows all current connections:

- username;
- IP address;
- session `SID`;
- connection time;
- active transport;
- current page;
- `sent/recv` traffic;
- subscription types:
  - properties;
  - objects;
  - actions;
  - data.

### 4.2. Monitoring

Allows you to watch WebSocket events in real time:

- pause and resume the event log;
- automatically create filters by event type;
- review recent messages stored in the page;
- visually distinguish events by color.

### 4.3. Settings

The `Settings` tab contains render optimization parameters:

- `Enable object render debounce` - enables/disables server-side debounce for `changeObject`;
- `Object render debounce (ms)` - debounce window in milliseconds;
- `Enable property change debounce` - enables/disables server-side debounce for `changeProperty`;
- `Property change debounce (ms)` - debounce window in milliseconds.

Default values:

- enabled: `true`;
- delay: `120 ms`.

For property debounce:

- enabled: `false`;
- delay: `80 ms`.

Recommended range: `80-300 ms`.

Property debounce recommended range: `40-150 ms`.

How it affects behavior:

- `changeProperty` can be coalesced per `Object.property` when property debounce is enabled;
- `changeObject` is coalesced per object and sent as the latest state after debounce;
- initial property value sent on `subscribeProperties` is still immediate (`sendProperty(...)`).

## 5. Module Widget

The `wsServer` widget shows a short summary of connected clients and updates through the `clients` event.

It is useful for:

- dashboards;
- system pages;
- quickly checking whether users are connected;
- reviewing which subscriptions a client is using.

## 6. Automatic Page Bindings

The module can update the DOM based on conventions used in templates.

### 6.1. Property binding by `id`

If the page contains:

```html
<span id="prop:Light1.state"></span>
```

then after subscribing, the server will send `changeProperty`, and the property value will be inserted into that element automatically.

Additional related fields are also supported:

```html
<span id="prop_changed:Light1.state"></span>
<span id="prop_source:Light1.state"></span>
```

### 6.2. Object binding by `id`

If the page contains a container like:

```html
<div id="obj:Light1"></div>
```

then when a `changeObject` event is received, its HTML will be re-rendered with `morphdom` without a full page reload.

### 6.3. Attribute bindings

Declarative bindings are supported:

```html
<div data-prop-display="Light1.online"></div>
<span data-prop-text="Weather.outdoorTemp"></span>
<input data-prop-value="Thermostat.targetTemp">
<input type="checkbox" data-prop-checked="Light1.enabled">
<a data-prop-attr-title="Light1.status"></a>
<img data-prop-attr-src="Camera1.preview">
```

These bindings work automatically after `subscribe()` is called.

## 7. User Scenarios

### 7.1. Display a live property value

Use:

```html
<span id="prop:Sensor1.temperature"></span>
```

or:

```html
<span data-prop-text="Sensor1.temperature"></span>
```

### 7.2. Dynamically show or hide a block

```html
<div
  data-prop-display="Pump1.enabled"
  data-prop-display-true="block"
  data-prop-display-false="none">
  Pump is enabled
</div>
```

### 7.3. Live update of object HTML

```html
<div id="obj:Heater1"></div>
```

When the object is re-rendered on the server, the client receives the new content automatically.

### 7.4. Receive system notifications

By default, the client subscribes to:

- `say`;
- `playsound`;
- `notify`.

Because of this, messages, system notifications, and sounds work on most pages without extra manual setup.

## 8. Example Client Connection

```javascript
const socket = io();

socket.on('connect', () => {
  socket.emit('subscribeProperties', ['Light1.state']);
  socket.emit('subscribeObjects', ['Light1']);
  socket.emit('subscribeActions', ['say', 'notify', 'playsound', 'executedMethod']);
  socket.emit('subscribeData', ['telemetry']);
});

socket.on('changeProperty', (data) => {
  console.log('Property changed', data);
});

socket.on('changeObject', (data) => {
  console.log('Object HTML updated', data.object);
});

socket.on('telemetry', (data) => {
  console.log('Telemetry', data);
});
```

## 9. Usage Recommendations

- use `subscribeProperties` for targeted value updates;
- use `subscribeObjects` when you need to recalculate and re-render a full HTML block;
- do not subscribe clients to `*` unless it is a monitoring screen;
- prefer `say` and `notify` for server-side notifications instead of arbitrary events;
- use separate channel names in `sendData(...)` for module-specific data streams.
