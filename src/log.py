import asyncio
import aiofiles
from collections import deque
from typing import Any, List, Literal
from utils import Parameters


class WazooLogHandler:
    params: List[Parameters]

    def __init__(self, prefix: str = "", add_new_line: bool = True) -> None:
        self.params: List[Parameters] = []
        self.prefix = prefix
        self._prefix = prefix.encode()
        self.new_line = add_new_line

    def configure(self, data: Any):
        if missing := next(
            (p.name for p in self.params if p.required and p.name not in data), None
        ):
            raise ValueError(f"Required param not provided: {missing}")

        for param in self.params:
            value = data.get(param.name, param.default)
            if value is None:
                continue
            if param.type is not None:
                if param.type is list:
                    value = [value] if not isinstance(value, list) else value
                else:
                    value = param.type(value)
            setattr(self, param.attr_name or param.name, value)

    async def connect(self):
        await self._configure()

    async def _configure(self):
        pass

    async def _close(self):
        pass

    async def sendLog(self, log: bytes):
        await self._sendLog(self._prefix + log + (b"\n" if self.new_line else b""))

    async def sendLogBatch(self, logs: deque[bytes]):
        suffix = b'\n' if self.new_line else b''
        log = b''.join(
            self._prefix + log + suffix
            for log in logs
        )
        await self._sendLog(log)

    async def _sendLog(self, log: bytes):
        raise NotImplementedError()


class WazooTcpHandler(WazooLogHandler):
    ip: str
    port: int
    ssl: bool

    def __init__(self, *args) -> None:
        super().__init__(*args)
        self.params.append(
            Parameters(name="ip", type=str, required=True, help="tcp ip")
        )
        self.params.append(
            Parameters(name="port", type=int, required=True, help="tcp port")
        )
        self.params.append(
            Parameters(
                name="ssl", type=bool, required=False, help="use ssl?", default=False
            )
        )

    async def _configure(self):
        self.socket = await asyncio.open_connection(
            self.ip, self.port, ssl=None if not self.ssl else True
        )

    async def _sendLog(self, log: bytes):
        _, writer = self.socket
        writer.write(log)
        await writer.drain()

    async def _close(self):
        _, writer = self.socket
        writer.close()
        await writer.wait_closed()


class WazooUdpHandler(WazooLogHandler):
    ip: str
    port: int

    def __init__(self, *args) -> None:
        super().__init__(*args)
        self.params.append(
            Parameters(name="ip", type=str, required=True, help="udp ip")
        )
        self.params.append(
            Parameters(name="port", type=int, required=True, help="udp port")
        )

    async def _configure(self):
        loop = asyncio.get_event_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, remote_addr=(self.ip, self.port)
        )

    async def _sendLog(self, log: bytes):
        self.transport.sendto(log)

    async def _close(self):
        self.transport.close()


class WazooUnixHandler(WazooLogHandler):
    path: str

    def __init__(self, *args) -> None:
        super().__init__(*args)
        self.params.append(
            Parameters(
                name="path",
                type=str,
                required=True,
                help="unix address like /var/wazoo.sock",
            )
        )

    async def _configure(self):
        self.socket = await asyncio.open_unix_connection(self.path)

    async def _sendLog(self, log: bytes):
        _, writer = self.socket
        writer.write(log)
        await writer.drain()

    async def _close(self):
        _, writer = self.socket
        writer.close()
        await writer.wait_closed()


class WazooFileHandler(WazooLogHandler):
    path: str

    def __init__(self, *args) -> None:
        super().__init__(*args)
        self.params.append(
            Parameters(
                name="path",
                type=str,
                required=True,
                help="file path to append",
            )
        )

    async def _configure(self):
        self.file_handler = await aiofiles.open(self.path, "ab")

    async def _sendLog(self, log: bytes):
        await self.file_handler.write(log)
        await self.file_handler.flush()

    async def _close(self):
        await self.file_handler.close()


class WazooLog:
    _servers: dict[str, type[WazooLogHandler]] = {
        "tcp": WazooTcpHandler,
        "udp": WazooUdpHandler,
        "unix": WazooUnixHandler,
        "file": WazooFileHandler,
    }

    def __init__(
        self,
        data: Any,
        option: Literal["tcp", "udp", "unix", "file"],
        add_new_line: bool = True,
        prefix: str = "",
    ) -> None:
        self.server = self._servers[option](prefix, add_new_line)
        self.server.configure(data)

    async def connect(self):
        await self.server.connect()

    async def sendLog(self, log: bytes):
        await self.server.sendLog(log)

    async def sendLogBatch(self, log: deque[bytes]):
        await self.server.sendLogBatch(log)

    async def close(self):
        if self.server is not None:
            await self.server._close()
