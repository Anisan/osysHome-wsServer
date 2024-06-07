""" Websocket module """

import datetime
from flask_socketio import SocketIO
from flask import render_template, request
from flask_login import current_user
from app.extensions import cache
from app.core.main.BasePlugin import BasePlugin
from app.core.lib.object import getObject,callMethod,setProperty


class wsServer(BasePlugin):
    """ Websocket Server module """

    def __init__(self,app):
        super().__init__(app,__name__)
        self.title = "Websocket"
        self.description = """Websocket server (SocketIO)"""
        self.category = "System"
        self.actions=['say','proxy']
        #Dictionary connected clients
        self.connected_clients = {}
        #ws
        self.socketio = SocketIO(logger=False, engineio_logger=False)
        self.register_websocket(app)

    def initialization(self) -> None:
        pass

    def admin(self, request) -> str:
        return render_template("ws_admin.html")

    def route_test(self):
        @self.blueprint.route("/ws_test")
        def wsTest():
            return render_template("ws_test.html")

    def register_websocket(self,app):
        """ Register websocket in app"""
        self.socketio.init_app(app)

        @self.socketio.on("connect")
        def handleConnect():
            try:
                if not current_user.is_authenticated:
                    return False
                self.logger.debug("Client %s(%s) connected", request.remote_addr, request.sid)
                #append connected clients
                self.connected_clients[request.sid] = {
                        "username": current_user.username,
                        "ip": request.remote_addr,
                        "connected": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "transport": self.socketio.server.transport(request.sid),
                        "subsProperties": [],
                        "subsObjects": [],
                    }
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("disconnect")
        def handleDisconnect():
            try:
                self.logger.debug("Client %s(%s) disconnected", request.remote_addr, request.sid)
                self.connected_clients.pop(request.sid, None)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("upgrade")
        def handleUpgrade(message):
            self.logger.debug(message)
        
        @self.socketio.on("message")
        def handleMessage(message):
            try:
                self.logger.debug("Received message: %s", message)
                self.socketio.emit("message", message)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("clients")
        def handleClients():
            try:
                self.logger.debug("Get clients")
                sid = request.sid
                for _,client in self.connected_clients.items():
                    client["transport"] = self.socketio.server.transport(request.sid)
                if current_user.role == "admin":
                    self.socketio.emit("clients", self.connected_clients, room=sid)
                else:
                    self.socketio.emit("clients", {}, room=sid)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        # TODO subscribe property
        @self.socketio.on("subscribeProperties")
        def handleSubscribeProperties(subsList):
            try:
                self.logger.debug("Received subscribe: %s", str(subsList))
                if request.sid in self.connected_clients:
                    client = self.connected_clients[request.sid]
                    sub = client["subsProperties"]
                    for prop in subsList:
                        if prop not in sub:
                            sub.append(prop)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("subscribeObjects")
        def handleSubscribeObjects(subsList):
            try:
                self.logger.debug("Received subscribe: %s", str(subsList))
                if request.sid in self.connected_clients:
                    client = self.connected_clients[request.sid]
                    sub = client["subsObjects"]
                    for prop in subsList:
                        if prop not in sub:
                            sub.append(prop)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("setProperty")
        def handleSetProperty(name, value):
            try:
                self.logger.debug("Received setProperty: %s=%s", name,value )
                setProperty(name, value, "WS")
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("callMethod")
        def handleCallMethod(name):
            try:
                self.logger.debug("Received callMethod: %s", name)
                callMethod(name)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

    def changeProperty(self, obj, prop, value):
        try:
            cache_render = None # cache.get(f"render_{obj}")
            name = obj + "." + prop
            for sid, client in list(self.connected_clients.items()):
                if name in client["subsProperties"]:
                    message = {
                        "property": name,
                        "value": str(value),
                    }
                    self.socketio.emit("changeProperty", message, room=sid)
                    self.logger.debug(message)
                if obj in client["subsObjects"]:
                    if not cache_render:
                        o = getObject(obj)
                        with self._app.app_context():
                            cache_render = o.render()
                        #cache.set(f"render_{obj}",cache_render,timeout=5)
                    message = {"object": obj, "value": cache_render}
                    self.socketio.emit("changeObject", message, room=sid)
        except Exception as ex:
            self.logger.exception(ex, exc_info=True)

    def say(self, message, level=0, destination=None):
        try:
            for sid, _ in list(self.connected_clients.items()):
                data = {
                        "message": message,
                        "level": level,
                        "destination": destination,
                }
                self.socketio.emit("say", data, room=sid)
        except Exception as ex:
            self.logger.exception(ex, exc_info=True)
