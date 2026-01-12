# wsServer - WebSocket Server Module

![wsServer Icon](static/wsServer.png)

WebSocket server based on SocketIO for real-time bidirectional communication between server and clients.

## Description

The `wsServer` module provides a full-featured WebSocket server for the osysHome system, enabling real-time communication between the server and client applications. The module is built on Flask-SocketIO and is fully integrated with the osysHome object system.

## Main Features

- ✅ **Client connection/disconnection** with user authentication
- ✅ **Event subscriptions**:
  - Object property changes (`subscribeProperties`)
  - Object changes (`subscribeObjects`)
  - Method execution (`subscribeActions`)
  - Custom data (`subscribeData`)
- ✅ **Client monitoring** with transport information and traffic statistics
- ✅ **Object management** via WebSocket:
  - Property setting (`setProperty`)
  - Method calling (`callMethod`)
- ✅ **Admin panel** for monitoring connected clients and events
- ✅ **LSP support** for code editors

## Events and Notifications

The module supports the following event types:

### Server to Client Events:

- `say` - sending text messages to clients
- `notify` - sending notifications
- `playsound` - playing sound files
- `changeProperty` - notification about object property changes
- `changeObject` - notification about object changes
- `executedMethod` - notification about method execution
- `clients` - information about connected clients

### Client to Server Events:

- `connect` - client connection
- `disconnect` - client disconnection
- `subscribeProperties` - subscription to property changes
- `subscribeObjects` - subscription to object changes
- `subscribeActions` - subscription to action execution
- `subscribeData` - subscription to custom data
- `setProperty` - setting property value
- `callMethod` - calling object method
- `clients` - requesting client list
- `lsp` - Language Server Protocol requests

## Admin Panel

The module includes an admin panel with two tabs:

### "Clients" Tab

Displays a list of all connected clients with information:
- Username
- IP address
- SID (Session ID)
- Connection time (Connected)
- Transport type (Transport)

### "Monitoring" Tab

Allows real-time monitoring of WebSocket events:
- **Pause/Resume** - control of new event display
- **Event filtering** - dynamic filters by event types (badges with color coding)
- **Event log** - display of all events with timestamps and data

## Technical Details

- **Technologies**: Flask-SocketIO, Socket.IO
- **Transports**: WebSocket, Long Polling (automatic fallback)
- **Security**: Authentication via Flask-Login
- **Statistics**: Tracking sent/received bytes for each client
- **Time zones**: Automatic timestamp conversion based on user timezone
- **Caching**: Caching sound files for playback

## Usage

### Connecting to WebSocket

```javascript
const socket = io();

socket.on('connect', function() {
    console.log('Connected');
    
    // Subscribe to property changes
    socket.emit('subscribeProperties', ['ObjectName.propertyName']);
    
    // Subscribe to all properties
    socket.emit('subscribeProperties', ['*']);
    
    // Subscribe to events
    socket.emit('subscribeActions', ['say', 'executedMethod']);
});

// Handle property change
socket.on('changeProperty', function(data) {
    console.log('Property changed:', data);
});

// Handle say event
socket.on('say', function(data) {
    console.log('Message:', data.message);
});
```

### Setting Property

```javascript
socket.emit('setProperty', 'ObjectName.propertyName', newValue, 'WS');
socket.on('propertyChanged', function(response) {
    if (response.success) {
        console.log('Property updated:', response.property, response.value);
    } else {
        console.error('Error:', response.error);
    }
});
```

### Calling Method

```javascript
socket.emit('callMethod', 'ObjectName.methodName', 'WS', false);
```

## Version

Current version: **1.1**

## Category

System

## Actions

The module provides the following actions for use by other modules:
- `say` - sending messages
- `proxy` - request proxying
- `playsound` - sound playback
- `widget` - module widget

## Requirements

- Flask-SocketIO
- Flask-Login (for authentication)
- osysHome system

## Author

Developed for osysHome

## License

See the main osysHome project license
