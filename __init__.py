""" Websocket module """
import json
import datetime
from flask_socketio import SocketIO
from flask import render_template, request
from flask_login import current_user
from app.core.utils import CustomJSONEncoder
from app.core.main.BasePlugin import BasePlugin
from app.core.lib.object import getObject, callMethod, setProperty


class wsServer(BasePlugin):
    """Websocket Server module"""

    def __init__(self, app):
        super().__init__(app, __name__)
        self.title = "Websocket"
        self.description = """Websocket server (SocketIO)"""
        self.category = "System"
        self.actions = ["say", "proxy"]
        # Dictionary connected clients
        self.connected_clients = {}
        # ws
        self.socketio = SocketIO(app, logger=False, engineio_logger=False, cors_allowed_origins="*")
        self.register_websocket(app)

    def initialization(self) -> None:
        pass

    def admin(self, request) -> str:
        return render_template("ws_admin.html")

    def route_test(self):
        @self.blueprint.route("/ws_test")
        def wsTest():
            return render_template("ws_test.html")

    def register_websocket(self, app):
        """Register websocket in app"""
        self.socketio.init_app(app)

        @self.socketio.on("connect")
        def handleConnect():
            try:
                if not current_user.is_authenticated:
                    return False
                self.logger.debug(
                    "Client %s(%s) connected", request.remote_addr, request.sid
                )
                # append connected clients
                self.connected_clients[request.sid] = {
                    "username": current_user.username,
                    "ip": request.remote_addr,
                    "connected": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "transport": self.socketio.server.transport(request.sid),
                    "subsProperties": [],
                    "subsObjects": [],
                    "subsData": [],
                }
                self.sendClientsInfo()
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("disconnect")
        def handleDisconnect():
            try:
                self.logger.debug(
                    "Client %s(%s) disconnected", request.remote_addr, request.sid
                )
                self.connected_clients.pop(request.sid, None)
                self.sendClientsInfo()
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("upgrade")
        def handleUpgrade(message):
            self.logger.debug(message)

        @self.socketio.on("restart_system")
        def handleRestart():
            self.logger.info("Command restart system from %s", current_user.username)
            if current_user.role == "admin":
                from app.admin.tools import restart_system

                res = restart_system()
                self.logger.info(res)

        @self.socketio.on("message")
        def handleMessage(message):
            try:
                self.logger.debug("Received message: %s", message)
                self.socketio.emit("message", message)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("clients")
        def handleClients():
            self.sendClientsInfo()

        # TODO subscribe property
        @self.socketio.on("subscribeProperties")
        def handleSubscribeProperties(subsList):
            try:
                self.logger.debug("Received subscribe: %s", str(subsList))
                if request.sid in self.connected_clients:
                    client = self.connected_clients[request.sid]
                    sub = client["subsProperties"]
                    subscribed = []
                    for obj_prop in subsList:
                        if obj_prop not in sub:
                            if obj_prop == '*':
                                continue
                            split = obj_prop.split(".")
                            if len(split) != 2:
                                continue
                            sub.append(obj_prop)
                            subscribed.append(obj_prop)
                            obj = split[0]
                            prop = split[1]
                            o = getObject(obj)
                            p = o.properties[prop]
                            message = {
                                "property": obj_prop,
                                "value": str(p.value),
                                "source": p.source,
                                "changed": str(p.changed),
                            }
                            self.socketio.emit("changeProperty", message, room=request.sid)
                    self.socketio.emit("subscribedProperties", subscribed, room=request.sid)
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

        @self.socketio.on("subscribeData")
        def handleSubscribeData(subsList):
            try:
                self.logger.debug("Received subscribe: %s", str(subsList))
                if request.sid in self.connected_clients:
                    client = self.connected_clients[request.sid]
                    sub = client["subsData"]
                    for prop in subsList:
                        if prop not in sub:
                            sub.append(prop)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("setProperty")
        def handleSetProperty(name, value, source="WS"):
            try:
                if not source:
                    source = "WS"
                self.logger.debug("Received setProperty: %s=%s (source: %s)", name, value, source)
                setProperty(name, value, source)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("callMethod")
        def handleCallMethod(name, source="WS", sendResult=False):
            try:
                if not source:
                    source = "WS"
                self.logger.debug("Received callMethod: %s (source: %s)", name, source)
                result = callMethod(name, source=source)
                if sendResult:
                    sid = request.sid
                    data = {"name": name, "data": result}
                    self.socketio.emit("resultCallMethod", data, room=sid)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

    def sendClientsInfo(self):
        try:
            self.logger.debug("Send clients")
            for sid, client in self.connected_clients.items():
                client["transport"] = self.socketio.server.transport(sid)
            for sid, client in list(self.connected_clients.items()):
                self.socketio.emit("clients", self.connected_clients, room=sid)
        except Exception as ex:
            self.logger.exception(ex, exc_info=True)

    def changeProperty(self, obj, prop, value):
        try:
            cache_render = None     # cache.get(f"render_{obj}")
            name = obj + "." + prop
            for sid, client in list(self.connected_clients.items()):
                if name in client["subsProperties"] or "*" in client["subsProperties"]:
                    o = getObject(obj)
                    p = o.properties[prop]
                    message = {
                        "property": name,
                        "value": str(value),
                        "source": p.source,
                        "changed": str(p.changed),
                    }
                    self.socketio.emit("changeProperty", message, room=sid)
                    self.logger.debug(message)
                if obj in client["subsObjects"] or "*" in client["subsObjects"]:
                    if not cache_render:
                        o = getObject(obj)
                        with self._app.app_context():
                            cache_render = o.render()
                        # cache.set(f"render_{obj}",cache_render,timeout=5)
                    message = {"object": obj, "value": cache_render}
                    self.socketio.emit("changeObject", message, room=sid)
        except Exception as ex:
            self.logger.exception(ex, exc_info=True)

    def executedMethod(self, obj, method):
        try:
            name = obj + "." + method
            o = getObject(obj)
            m = o.methods[method]
            message = {
                "method": name,
                "source": m.source,
                "executed": str(m.executed),
                "exec_params": json.dumps(m.exec_params, cls=CustomJSONEncoder),
                "exec_result": m.exec_result,
            }
            self.logger.debug(message)
            for sid, _ in list(self.connected_clients.items()):
                self.socketio.emit("executedMethod", message, room=sid)
        except Exception as ex:
            self.logger.exception(ex, exc_info=True)

    def say(self, message, level=0, args=None):
        try:
            for sid, _ in list(self.connected_clients.items()):
                data = {"message": message, "level": level, "args": args}
                self.socketio.emit("say", data, room=sid)
        except Exception as ex:
            self.logger.exception(ex, exc_info=True)

    def sendData(self, typeData, data) -> bool:
        """Send data to websocket
        Args:
            typeData (str): Type data
            data (any): Data
        Returns:
            bool: Success
        """
        try:
            for sid, client in list(self.connected_clients.items()):
                if typeData in client["subsData"] or "*" in client["subsData"]:
                    self.socketio.emit(typeData, data, room=sid)
            return True
        except Exception as ex:
            self.logger.exception(ex, exc_info=True)
            return False

    def sendCommand(self, command, data, client_id=None) -> bool:
        """Send command to websocket
        Args:
            command (str): Command
            data (any): Data
            client_id(str): Client ID (None - send all)
        Returns:
            bool: Success
        """
        try:
            for sid, _ in list(self.connected_clients.items()):
                if client_id is None or sid == client_id:
                    self.socketio.emit(command, data, room=sid)
            return True
        except Exception as ex:
            self.logger.exception(ex, exc_info=True)
            return False
