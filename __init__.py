"""
Websocket module

WebSocket сервер на базе SocketIO для обеспечения двусторонней связи между сервером
и клиентами в реальном времени. Модуль предоставляет функциональность для:

Основные возможности:
- Подключение/отключение клиентов с аутентификацией
- Подписки на изменения свойств объектов (subscribeProperties)
- Подписки на изменения объектов (subscribeObjects)
- Подписки на выполнение методов (subscribeMethods)
- Подписки на действия say/notify/playsound (subscribeActions)
- Подписки на пользовательские данные (subscribeData)
- Мониторинг подключенных клиентов с информацией о транспорте и статистике
- Установка свойств объектов через WebSocket (setProperty)
- Вызов методов объектов через WebSocket (callMethod)

События и уведомления:
- say: отправка текстовых сообщений клиентам
- notify: отправка уведомлений
- playSound: воспроизведение звуковых файлов
- changeProperty: уведомление об изменении свойств
- changeObject: уведомление об изменении объектов
- executedMethod: уведомление о выполнении методов

Дополнительные функции:
- LSP (Language Server Protocol) поддержка для редакторов кода
- Статистика трафика (отправленные/полученные байты)
- Конвертация временных меток с учетом часового пояса пользователя
- Кэширование звуковых файлов для воспроизведения
- Административная панель для мониторинга клиентов и событий

Технические детали:
- Использует Flask-SocketIO для WebSocket соединений
- Поддерживает различные транспортные протоколы (WebSocket, Long Polling)
- Интегрирован с системой объектов osysHome
- Обеспечивает безопасность через аутентификацию пользователей
"""
import os
import json
import datetime
import threading
from flask_socketio import SocketIO, ConnectionRefusedError
from app.authentication.handlers import handle_user_required

from flask import render_template, request, send_file, abort
from flask_login import current_user
from app.database import convert_utc_to_local, get_now_to_utc
from app.logging_config import security_audit_log
from app.core.utils import CustomJSONEncoder
from app.core.main.BasePlugin import BasePlugin
from app.core.lib.object import getObject, callMethod, getProperty
from app.extensions import cache
from app.core.lsp_client import run_lsp_action


class wsServer(BasePlugin):
    """Websocket Server module"""

    def __init__(self, app):
        super().__init__(app, __name__)
        self.title = "Websocket"
        self.description = """Websocket server (SocketIO)"""
        self.category = "System"
        self.version = "1.1"
        self.actions = ["say", "proxy", "playsound", "widget"]
        # Dictionary connected clients
        self.connected_clients = {}
        # Last sent rendered HTML per object for changeObject de-duplication
        self._last_object_render = {}
        # Last sent property state per Object.property for changeProperty de-duplication
        self._last_property_state = {}
        # Pending per-object timers for changeObject debounce
        self._pending_object_timers = {}
        self._pending_object_timers_lock = threading.Lock()
        # Pending per-property timers for changeProperty debounce
        self._pending_property_timers = {}
        self._pending_property_timers_lock = threading.Lock()
        # ws
        self.socketio = SocketIO(app, logger=False, engineio_logger=False, cors_allowed_origins="*")
        self.register_websocket(app)

    def initialization(self) -> None:
        if "object_render_debounce_enabled" not in self.config:
            self.config["object_render_debounce_enabled"] = True
        if "object_render_debounce_ms" not in self.config:
            self.config["object_render_debounce_ms"] = 120
        if "property_change_debounce_enabled" not in self.config:
            self.config["property_change_debounce_enabled"] = False
        if "property_change_debounce_ms" not in self.config:
            self.config["property_change_debounce_ms"] = 80
        self.saveConfig()

    def admin(self, request) -> str:
        if request.method == "POST":
            try:
                enabled = request.form.get("object_render_debounce_enabled") == "on"
                try:
                    debounce_ms = int(request.form.get("object_render_debounce_ms", 120))
                except (TypeError, ValueError):
                    debounce_ms = 120
                debounce_ms = max(0, min(5000, debounce_ms))

                prop_enabled = request.form.get("property_change_debounce_enabled") == "on"
                try:
                    prop_debounce_ms = int(request.form.get("property_change_debounce_ms", 80))
                except (TypeError, ValueError):
                    prop_debounce_ms = 80
                prop_debounce_ms = max(0, min(5000, prop_debounce_ms))

                self.config["object_render_debounce_enabled"] = enabled
                self.config["object_render_debounce_ms"] = debounce_ms
                self.config["property_change_debounce_enabled"] = prop_enabled
                self.config["property_change_debounce_ms"] = prop_debounce_ms
                self.saveConfig()
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        content = {
            "object_render_debounce_enabled": bool(self.config.get("object_render_debounce_enabled", True)),
            "object_render_debounce_ms": int(self.config.get("object_render_debounce_ms", 120)),
            "property_change_debounce_enabled": bool(self.config.get("property_change_debounce_enabled", False)),
            "property_change_debounce_ms": int(self.config.get("property_change_debounce_ms", 80)),
        }
        return render_template("ws_admin.html", **content)

    def widget(self):
        return render_template("widget_ws.html")

    def register_websocket(self, app):
        """Register websocket in app"""
        self.socketio.init_app(app)

        @self.socketio.on("connect")
        def handleConnect():
            try:
                if not current_user.is_authenticated:
                    ip = request.remote_addr or '?'
                    security_audit_log('WS_UNAUTHORIZED', ip=ip, endpoint='ws_connect', reason='not_authenticated')
                    raise ConnectionRefusedError('Unauthorized')
                self.logger.debug(
                    "Client %s(%s) connected", request.remote_addr, request.sid
                )
                # append connected clients
                self.connected_clients[request.sid] = {
                    "username": current_user.username,
                    "ip": request.remote_addr,
                    "connected": get_now_to_utc().strftime("%Y-%m-%d %H:%M:%S"),
                    "transport": self.socketio.server.transport(request.sid),
                    "page": request.path,
                    "stats": {"recvBytes": 0, "sentBytes": 0},
                    "subsProperties": [],
                    "subsObjects": [],
                    "subsMethods": [],
                    "subsData": [],
                    "subsActions": [],
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

        @self.socketio.on("clients")
        def handleClients():
            self.incrementRecv(request.sid,"clients")
            self.sendClientsInfo(request.sid)

        @self.socketio.on("page")
        def handlePage(page):
            """Update current page/URL for connected client."""
            self.incrementRecv(request.sid, "page", page)
            try:
                if request.sid in self.connected_clients:
                    self.connected_clients[request.sid]["page"] = page
                    # Обновляем информацию о клиентах для всех слушателей
                    self.sendClientsInfo()
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        # TODO subscribe property
        @self.socketio.on("subscribeProperties")
        def handleSubscribeProperties(subsList):
            self.incrementRecv(request.sid,"subscribeProperties",subsList)
            try:
                self.logger.debug("Received subscribe: %s", str(subsList))
                if request.sid in self.connected_clients:
                    client = self.connected_clients[request.sid]
                    sub = client["subsProperties"]
                    subscribed = []
                    for obj_prop in subsList:
                        if obj_prop not in sub:
                            if obj_prop == '*':
                                sub.append(obj_prop)
                                continue
                            if "." not in obj_prop:
                                continue
                            sub.append(obj_prop)
                            subscribed.append(obj_prop)
                            self.sendProperty(request.sid, obj_prop)
                        else:
                            subscribed.append(obj_prop)
                            self.sendProperty(request.sid, obj_prop)

                    self.socketio.emit("subscribedProperties", subscribed, room=request.sid)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("subscribeObjects")
        def handleSubscribeObjects(subsList):
            self.incrementRecv(request.sid,"subscribeObjects",subsList)
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

        @self.socketio.on("unsubscribeProperties")
        def handleUnsubscribeProperties(unsubsList):
            self.incrementRecv(request.sid,"unsubscribeProperties",unsubsList)
            try:
                self.logger.debug("Received unsubscribe properties: %s", str(unsubsList))
                if request.sid in self.connected_clients:
                    client = self.connected_clients[request.sid]
                    sub = client["subsProperties"]
                    for obj_prop in unsubsList:
                        if obj_prop in sub:
                            sub.remove(obj_prop)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("unsubscribeObjects")
        def handleUnsubscribeObjects(unsubsList):
            self.incrementRecv(request.sid,"unsubscribeObjects",unsubsList)
            try:
                self.logger.debug("Received unsubscribe objects: %s", str(unsubsList))
                if request.sid in self.connected_clients:
                    client = self.connected_clients[request.sid]
                    sub = client["subsObjects"]
                    for prop in unsubsList:
                        if prop in sub:
                            sub.remove(prop)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("subscribeMethods")
        def handleSubscribeMethods(subsList):
            self.incrementRecv(request.sid, "subscribeMethods", subsList)
            try:
                self.logger.debug("Received subscribe methods: %s", str(subsList))
                if request.sid in self.connected_clients:
                    client = self.connected_clients[request.sid]
                    sub = client["subsMethods"]
                    subscribed = []
                    for obj_method in subsList:
                        if obj_method not in sub:
                            if obj_method == '*':
                                sub.append(obj_method)
                                subscribed.append(obj_method)
                                continue
                            split = obj_method.split(".")
                            if len(split) != 2:
                                continue
                            sub.append(obj_method)
                            subscribed.append(obj_method)
                            self.sendMethod(request.sid, obj_method)
                        else:
                            subscribed.append(obj_method)
                            self.sendMethod(request.sid, obj_method)

                    self.socketio.emit("subscribedMethods", subscribed, room=request.sid)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("unsubscribeMethods")
        def handleUnsubscribeMethods(unsubsList):
            self.incrementRecv(request.sid, "unsubscribeMethods", unsubsList)
            try:
                self.logger.debug("Received unsubscribe methods: %s", str(unsubsList))
                if request.sid in self.connected_clients:
                    client = self.connected_clients[request.sid]
                    sub = client["subsMethods"]
                    for obj_method in unsubsList:
                        if obj_method in sub:
                            sub.remove(obj_method)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("subscribeActions")
        def handleSubscribeActions(subsList):
            self.incrementRecv(request.sid,"subscribeActions",subsList)
            try:
                self.logger.debug("Received subscribe actions: %s", str(subsList))
                if request.sid in self.connected_clients:
                    client = self.connected_clients[request.sid]
                    sub = client["subsActions"]
                    for action in subsList:
                        if action == "executedMethod":
                            # Backward compatibility: old clients used subscribeActions.
                            method_sub = client["subsMethods"]
                            if "*" not in method_sub:
                                method_sub.append("*")
                            continue
                        if action not in sub:
                            sub.append(action)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("unsubscribeActions")
        def handleUnsubscribeActions(unsubsList):
            self.incrementRecv(request.sid,"unsubscribeActions",unsubsList)
            try:
                self.logger.debug("Received unsubscribe actions: %s", str(unsubsList))
                if request.sid in self.connected_clients:
                    client = self.connected_clients[request.sid]
                    sub = client["subsActions"]
                    for action in unsubsList:
                        if action == "executedMethod":
                            method_sub = client["subsMethods"]
                            if "*" in method_sub:
                                method_sub.remove("*")
                            continue
                        if action in sub:
                            sub.remove(action)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("subscribeData")
        def handleSubscribeData(subsList):
            self.incrementRecv(request.sid,"subscribeData",subsList)
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

        @self.socketio.on("unsubscribeData")
        def handleUnsubscribeData(unsubsList):
            self.incrementRecv(request.sid,"unsubscribeData",unsubsList)
            try:
                self.logger.debug("Received unsubscribe data: %s", str(unsubsList))
                if request.sid in self.connected_clients:
                    client = self.connected_clients[request.sid]
                    sub = client["subsData"]
                    for prop in unsubsList:
                        if prop in sub:
                            sub.remove(prop)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)

        @self.socketio.on("setProperty")
        def handleSetProperty(name, value, source="WS"):
            """
            Установка значения свойства через WebSocket.

            Важно: здесь мы вызываем ObjectManager.setProperty напрямую,
            чтобы не потерять текст ошибок валидации (ValueError, PermissionError и т.п.).
            Обертка app.core.lib.object.setProperty перехватывает все исключения и
            возвращает только bool, поэтому для UX в админке используем прямой вызов.
            """
            self.incrementRecv(request.sid, "setProperty", value)
            try:
                if not source:
                    source = "WS"

                self.logger.debug(
                    "Received setProperty: %s=%s (source: %s)", name, value, source
                )

                # Разбираем имя вида "Object.Property"
                if not isinstance(name, str) or "." not in name:
                    raise ValueError(f"Invalid property name format: '{name}'")

                object_name, prop_name = name.split(".", 1)
                obj = getObject(object_name)
                if not obj:
                    raise ValueError(f"Object '{object_name}' not found")

                # Вызов ObjectManager.setProperty, который теперь пробрасывает ValueError
                obj.setProperty(prop_name, value, source)

                # Успешное обновление
                self.socketio.emit(
                    "propertyChanged",
                    {
                        "success": True,
                        "property": name,
                        "value": value,
                    },
                    room=request.sid,
                )

            except (ValueError, PermissionError, TypeError) as ex:
                # Ошибки валидации - отправляем клиенту текст исключения
                self.logger.warning("Validation error for %s: %s", name, str(ex))
                self.socketio.emit(
                    "propertyChanged",
                    {
                        "success": False,
                        "property": name,
                        "error": str(ex),
                    },
                    room=request.sid,
                )
            except Exception as ex:
                # Прочие ошибки - логируем и отправляем общее сообщение
                self.logger.exception(ex, exc_info=True)
                self.socketio.emit(
                    "propertyChanged",
                    {
                        "success": False,
                        "property": name,
                        "error": f"Server error: {str(ex)}",
                    },
                    room=request.sid,
                )

        @self.socketio.on("callMethod")
        def handleCallMethod(name, source="WS", sendResult=False):
            self.incrementRecv(request.sid,"callMethod")
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

        @self.socketio.on("lsp")
        def handleLsp(payload=None):
            self.incrementRecv(request.sid, "lsp", payload)
            request_id = None
            try:
                payload = payload or {}
                request_id = payload.get("requestId")
                result = self._handle_lsp_request(payload)
                result["requestId"] = request_id
                self.socketio.emit("lsp", result, room=request.sid)
            except Exception as ex:
                self.logger.exception(ex, exc_info=True)
                self.socketio.emit(
                    "lsp",
                    {"success": False, "error": str(ex), "requestId": request_id},
                    room=request.sid,
                )

        # Модификация метода emit для подсчета отправленных байт
        original_emit = self.socketio.emit

        def custom_emit(*args, **kwargs):
            """Модифицированный emit для подсчета отправленных байт."""
            client_id = kwargs.get('room')  # Получаем ID клиента (если указано)

            # Если клиент указан и он существует в статистике
            if client_id and client_id in self.connected_clients:
                # Подсчитываем размер данных
                data_to_send = args[1:] if len(args) > 1 else args[0]
                sent_bytes = sum(len(str(d).encode('utf-8')) for d in data_to_send if d is not None)

                # Обновляем счетчик отправленных байт
                self.connected_clients[client_id]['stats']['sentBytes'] += sent_bytes

            # Вызываем оригинальный emit
            return original_emit(*args, **kwargs)

        self.socketio.emit = custom_emit

    def incrementRecv(self, client_id, message, data=None):
        # Если клиент указан и он существует в статистике
        if client_id and client_id in self.connected_clients:
            # Подсчитываем размер данных
            length_data = len(message)
            if data:
                length_data += len(str(data).encode('utf-8'))
            # Обновляем счетчик полученных байт
            self.connected_clients[client_id]['stats']['recvBytes'] += length_data

    def _getTimezone(self, username):
        if username:
            timezone = cache.get(f"{username}.timezone")
            if not timezone:
                timezone = getProperty(f"{username}.timezone")
                if timezone:
                    cache.set(f"{username}.timezone", timezone, timeout=3600)
            return timezone
        return 'UTC'

    def sendMethod(self, sid, obj_method):
        split = obj_method.split(".")
        if len(split) != 2:
            return False
        obj = split[0]
        method = split[1]
        o = getObject(obj)
        if o and method in o.methods:
            username = self.connected_clients[sid]['username']
            timezone = self._getTimezone(username)
            m = o.methods[method]
            message = {
                "method": obj_method,
                "source": m.source,
                "executed": str(convert_utc_to_local(m.executed, timezone)),
                "exec_params": json.dumps(m.exec_params, cls=CustomJSONEncoder),
                "exec_result": m.exec_result,
                "exec_time": m.exec_time,
            }
            self.socketio.emit("executedMethod", message, room=sid)
            return True
        return False

    def sendProperty(self, sid, obj_prop):
        if "." not in obj_prop:
            return False
        obj, prop = obj_prop.rsplit(".", 1)
        o = getObject(obj)
        if o:
            if prop in o.properties:
                username = self.connected_clients[sid]['username']

                timezone = self._getTimezone(username)
                p = o.properties[prop]
                value = p.getValue()
                message = {
                    "property": obj_prop,
                    "value": str(value) if isinstance(value, datetime.datetime) else value,
                    "source": p.source,
                    "changed": str(convert_utc_to_local(p.changed, timezone)),
                }
                self.socketio.emit("changeProperty", message, room=sid)
                return True
        return False

    def sendClientsInfo(self, room=None):
        try:
            self.logger.debug("Send clients")
            for sid, client in self.connected_clients.items():
                client["transport"] = self.socketio.server.transport(sid)
            if room:
                self.socketio.emit("clients", self.connected_clients, room=room)
                return
            for sid, client in list(self.connected_clients.items()):
                self.socketio.emit("clients", self.connected_clients, room=sid)
        except Exception as ex:
            self.logger.exception(ex, exc_info=True)

    def changeProperty(self, obj, prop, value):
        """
        Send changeProperty and changeObject notifications to subscribed clients.

        Handles errors separately for each notification type to ensure partial failures
        don't block other notifications.
        """
        name = obj + "." + prop

        # Build subscriber lists first to avoid unnecessary rendering work.
        property_subscribers = []
        object_subscribers = []
        for sid, client in list(self.connected_clients.items()):
            if name in client["subsProperties"] or "*" in client["subsProperties"]:
                property_subscribers.append((sid, client))
            if obj in client["subsObjects"] or "*" in client["subsObjects"]:
                object_subscribers.append((sid, client))

        if property_subscribers:
            prop_debounce_enabled = bool(self.config.get("property_change_debounce_enabled", False))
            prop_debounce_ms = int(self.config.get("property_change_debounce_ms", 80) or 0)
            if prop_debounce_enabled and prop_debounce_ms > 0:
                self._schedule_change_property_emit(obj, prop, prop_debounce_ms)
            else:
                # Keep core update path responsive: emit in background when debounce is off.
                self.socketio.start_background_task(self._emit_change_property_now, obj, prop, value)

        # Send changeObject only when there are object subscribers and render changed.
        if object_subscribers:
            debounce_enabled = bool(self.config.get("object_render_debounce_enabled", True))
            debounce_ms = int(self.config.get("object_render_debounce_ms", 120) or 0)
            if debounce_enabled and debounce_ms > 0:
                self._schedule_change_object_emit(obj, debounce_ms)
            else:
                # Keep core update path responsive: render/emit in background when debounce is off.
                self.socketio.start_background_task(self._emit_change_object_now, obj)

    def _get_object_subscribers(self, obj):
        subscribers = []
        for sid, client in list(self.connected_clients.items()):
            if obj in client["subsObjects"] or "*" in client["subsObjects"]:
                subscribers.append((sid, client))
        return subscribers

    def _get_property_subscribers(self, property_name):
        subscribers = []
        for sid, client in list(self.connected_clients.items()):
            if property_name in client["subsProperties"] or "*" in client["subsProperties"]:
                subscribers.append((sid, client))
        return subscribers

    def _get_method_subscribers(self, method_name):
        subscribers = []
        for sid, client in list(self.connected_clients.items()):
            if method_name in client["subsMethods"] or "*" in client["subsMethods"]:
                subscribers.append((sid, client))
        return subscribers

    def _emit_change_property_now(self, obj, prop, value_hint=None):
        name = obj + "." + prop
        try:
            subscribers = self._get_property_subscribers(name)
            if not subscribers:
                return

            o = getObject(obj)
            if o is None:
                self.logger.warning(f"Object '{obj}' not found when emitting changeProperty for {name}")
                return
            if prop not in o.properties:
                self.logger.warning(f"Property '{prop}' not found in object '{obj}' when emitting changeProperty")
                return

            p = o.properties[prop]
            raw_value = p.getValue() if value_hint is None else value_hint
            state = (
                str(raw_value) if isinstance(raw_value, datetime.datetime) else raw_value,
                p.source,
                str(p.changed) if p.changed else None,
            )
            if self._last_property_state.get(name) == state:
                return
            self._last_property_state[name] = state

            for sid, client in subscribers:
                try:
                    username = client["username"]
                    timezone = self._getTimezone(username)
                    message = {
                        "property": name,
                        "value": state[0],
                        "source": p.source,
                        "changed": str(convert_utc_to_local(p.changed, timezone)),
                    }
                    self.socketio.emit("changeProperty", message, room=sid)
                    self.logger.debug(message)
                except Exception as ex:
                    self.logger.exception(f"Error sending changeProperty for {name} to client {sid}: {ex}", exc_info=True)
        except Exception as ex:
            self.logger.exception(f"Error in _emit_change_property_now for {name}: {ex}", exc_info=True)

    def _schedule_change_property_emit(self, obj, prop, debounce_ms):
        name = obj + "." + prop
        delay_s = max(0, debounce_ms) / 1000.0
        with self._pending_property_timers_lock:
            old_timer = self._pending_property_timers.get(name)
            if old_timer:
                old_timer.cancel()

            timer = threading.Timer(delay_s, lambda: self._flush_change_property_emit(obj, prop))
            timer.daemon = True
            self._pending_property_timers[name] = timer
            timer.start()

    def _flush_change_property_emit(self, obj, prop):
        name = obj + "." + prop
        with self._pending_property_timers_lock:
            self._pending_property_timers.pop(name, None)
        self._emit_change_property_now(obj, prop)

    def _emit_change_object_now(self, obj):
        try:
            subscribers = self._get_object_subscribers(obj)
            if not subscribers:
                return

            o = getObject(obj)
            if o is None:
                self.logger.warning(f"Object '{obj}' not found when emitting changeObject")
                return

            with self._app.app_context():
                cache_render = o.render()

            if cache_render is None:
                return
            if self._last_object_render.get(obj) == cache_render:
                return

            self._last_object_render[obj] = cache_render
            message = {"object": obj, "value": cache_render}
            for sid, _client in subscribers:
                try:
                    self.socketio.emit("changeObject", message, room=sid)
                except Exception as ex:
                    self.logger.exception(f"Error sending changeObject for '{obj}' to client {sid}: {ex}", exc_info=True)
        except Exception as ex:
            self.logger.exception(f"Error in _emit_change_object_now for '{obj}': {ex}", exc_info=True)

    def _schedule_change_object_emit(self, obj, debounce_ms):
        delay_s = max(0, debounce_ms) / 1000.0
        with self._pending_object_timers_lock:
            old_timer = self._pending_object_timers.get(obj)
            if old_timer:
                old_timer.cancel()

            timer = threading.Timer(delay_s, lambda: self._flush_change_object_emit(obj))
            timer.daemon = True
            self._pending_object_timers[obj] = timer
            timer.start()

    def _flush_change_object_emit(self, obj):
        with self._pending_object_timers_lock:
            self._pending_object_timers.pop(obj, None)
        self._emit_change_object_now(obj)

    def executedMethod(self, obj, method):
        try:
            name = obj + "." + method
            subscribers = self._get_method_subscribers(name)
            if not subscribers:
                return

            o = getObject(obj)
            if o is None or method not in o.methods:
                return

            m = o.methods[method]
            base_message = {
                "method": name,
                "source": m.source,
                "exec_params": json.dumps(m.exec_params, cls=CustomJSONEncoder),
                "exec_result": m.exec_result,
                "exec_time": m.exec_time,
            }
            self.logger.debug(base_message)
            for sid, client in subscribers:
                username = client["username"]
                timezone = self._getTimezone(username)
                message = dict(base_message)
                message["executed"] = str(convert_utc_to_local(m.executed, timezone))
                self.socketio.emit("executedMethod", message, room=sid)
        except Exception as ex:
            self.logger.exception(ex, exc_info=True)

    def say(self, message, level=0, args=None):
        try:
            for sid, client in list(self.connected_clients.items()):
                if "say" not in client["subsActions"]:
                    continue
                data = {"message": message, "level": level, "args": args}
                self.socketio.emit("say", data, room=sid)
        except Exception as ex:
            self.logger.exception(ex, exc_info=True)

    def notify(self, data:dict):
        try:
            for sid, client in list(self.connected_clients.items()):
                if "notify" not in client["subsActions"]:
                    continue
                self.socketio.emit("notify", data, room=sid)
        except Exception as ex:
            self.logger.exception(ex, exc_info=True)

    def playSound(self, file_name:str, level:int=0, args=None):
        try:
            for sid, client in list(self.connected_clients.items()):
                if "playsound" not in client["subsActions"]:
                    continue
                file_url = os.path.basename(file_name)
                cache.set("ws:cache:" + file_url, file_name)
                file_url = "/sound/" + os.path.basename(file_name)
                data = {"file_url": file_url, "level": level, "args": args}
                self.socketio.emit("playsound", data, room=sid)
        except Exception as ex:
            self.logger.exception(ex, exc_info=True)

    def route_index(self):
        @self.blueprint.route('/sound/<path:filename>', methods=["GET"])
        @handle_user_required
        def avatars(filename):
            file_path = cache.get("ws:cache:" + filename)
            if not file_path:
                abort(404, description="File not found in cache")
            from app.configuration import Config
            full_path = os.path.join(Config.APP_DIR,file_path)
            return send_file(full_path)

    def sendData(self, typeData, data) -> bool:
        """Send data to websocket
        Args:
            typeData (str): Type data
            data (any): Data
        Returns:
            bool: Success
        """
        try:
            # Skip if no clients are subscribed to this typeData (e.g. z2m page closed)
            has_subscribers = any(
                typeData in client.get("subsData", []) or "*" in client.get("subsData", [])
                for client in self.connected_clients.values()
            )
            if not has_subscribers:
                return True

            def dict_format(value, timezone):
                """
                Recursively walk through payload and:
                - convert datetime to localized string
                - convert date to ISO string
                - handle dicts, lists, tuples, sets
                Returns a new structure without mutating the original.
                """
                if isinstance(value, dict):
                    return {
                        k: dict_format(v, timezone)
                        for k, v in value.items()
                    }
                if isinstance(value, (list, tuple, set)):
                    container_type = type(value)
                    return container_type(dict_format(v, timezone) for v in value)
                if isinstance(value, datetime.datetime):
                    return str(convert_utc_to_local(value, timezone))
                if isinstance(value, datetime.date):
                    return value.isoformat()
                return value

            for sid, client in list(self.connected_clients.items()):
                username = client["username"]
                timezone = self._getTimezone(username)
                # Build a JSON‑serializable payload per client without mutating the original data
                payload = dict_format(data, timezone)
                if typeData in client["subsData"] or "*" in client["subsData"]:
                    self.socketio.emit(typeData, payload, room=sid)
            return True
        except Exception as ex:
            self.logger.exception(ex, exc_info=True)
            return False

    def _handle_lsp_request(self, payload):
        """Обработка LSP запроса через вебсокет"""
        payload = payload or {}
        action = payload.get("action")
        code = payload.get("code", "")
        line = payload.get("line")
        column = payload.get("column")
        timeout = payload.get("timeout", 1.5)
        object_name = payload.get("object_name")
        module_name = payload.get("module_name")
        exclude_custom_function = payload.get("exclude_custom_function")
        result = run_lsp_action(
            action,
            code,
            line=line,
            column=column,
            timeout=timeout,
            object_name=object_name,
            module_name=module_name,
            exclude_custom_function=exclude_custom_function,
        )
        result["success"] = True
        return result

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
