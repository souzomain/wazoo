import secrets
import logging
import asyncio
import os
import re
import ssl
from .wazuh.agent import WazuhAgent, WazuhAgentRepository
from .wazuh.helper import DecodedMessage, WazuhHelper
from .wazuh.enum import WazuhRcEventBytes
from .log import WazooLog
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from .buffer import BufferQueue

logger = logging.getLogger()

_OFFLOAD_THRESHOLD = 4096


class WazuhServer:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port_registration: int = 1515,
        port_logging: int = 1514,
        password: str | None = None,
        client_keys: str | None = None,
        ssl_path: Path = Path("./ssl"),
        version: str = "4.14.5",
        manager_name: str = "manager",
        db_path: str | Path = "agents.db",
        reuse_port: bool = False,
        log: WazooLog | None = None,
        workers: int | None = None,
        max_time_flush: int = 1,
        max_line_flush: int = -1,
    ) -> None:
        if workers and workers <= 0:
            workers = os.cpu_count()
        if not client_keys or len(client_keys) == 0:
            client_keys = "client.keys"

        self.host = host
        self.port_registration = port_registration
        self.port_logging = port_logging
        self.reuse_port = reuse_port
        self.password = None if not password else password.strip()
        self.client_keys = Path(client_keys)
        self.log = log
        self.ssl_path = ssl_path
        self.ssl_key = Path(ssl_path) / "key.pem"
        self.ssl_cert = Path(ssl_path) / "cert.pem"
        self.buffer_queue = (
            BufferQueue(self.log.sendLogBatch, max_time_flush, max_line_flush)
            if self.log
            else None
        )
        self.workers = workers

        if not ssl_path.exists():
            raise Exception("SSL path not exists")
        if not ssl_path.is_dir():
            raise Exception("SSL path is not an directory")
        if not self.ssl_key.exists():
            raise FileNotFoundError("SSL key.pem does not exists")
        if not self.ssl_cert.exists():
            raise FileNotFoundError("SSL cert.pem does not exists")

        self.agents = WazuhAgentRepository(db_path)
        self._sync_agents_from_client_keys()
        if self.agents.get(0) is None:
            self.agents.add(
                WazuhAgent(
                    id=0,
                    key=self.generate_random_agent_key().encode(),
                    name=manager_name,
                    version=version,
                )
            )

        if self.password:
            logger.info('Server configured with password')
            logger.debug(f'Password: {self.password}')


    def getAgentId(self, id: int):
        return self.agents.get(id)

    def generate_random_agent_key(self):
        return secrets.token_hex(32)

    def add_new_agent(self, name: str, version: str) -> WazuhAgent:
        agent = WazuhAgent(
            key=self.generate_random_agent_key().encode(), name=name, version=version
        )
        return self.agents.add(agent)

    @staticmethod
    def _parse_client_keys_line(line: str) -> tuple[int, str, bytes] | None:
        parts = line.split()
        if len(parts) != 4:
            return None
        agent_id, name, _ip, key = parts
        return int(agent_id), name, key.encode()

    def _sync_agents_from_client_keys(self) -> None:
        if not self.client_keys.exists():
            return
        for line in self.client_keys.read_text().splitlines():
            parsed = self._parse_client_keys_line(line)
            if parsed is None:
                continue
            agent_id, name, key = parsed
            if self.agents.get(agent_id) is not None:
                continue
            self.agents.add(WazuhAgent(id=agent_id, key=key, name=name, version=""))

    def _append_client_keys_line(self, agent: WazuhAgent) -> None:
        line = f"{agent.id:03d} {agent.name} any {agent.key.decode()}\n"
        with self.client_keys.open("a") as f:
            f.write(line)

    def parse_wazuh_registration_message(self, text: str) -> dict:
        text = text.strip()
        password = None
        pass_match = re.search(r"PASS:\s*(\S+)\s*", text)
        if pass_match:
            password = pass_match.group(1)

        message_id, rest = text.split(maxsplit=1)
        result = {
            "message_id": message_id,
            **dict(re.findall(r"(\w+):'([^']*)'", rest)),
        }

        if password:
            result["password"] = password
        return result

    # register connection server 1515
    async def _r_connection_callback(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        # OSSEC A:'wazuh-agent-souzo-arch' V:'v4.14.5' G:'default'\n
        addr = writer.get_extra_info("peername")
        try:
            logger.info(f"Connection received: registration server. {addr}")
            data = await reader.readline()
            logger.debug("Wazuh data: %s", data)
            parsed_message = self.parse_wazuh_registration_message(data.decode())
            logger.debug(f"agent parsed message: {parsed_message}")

            if not {"A", "V"}.issubset(parsed_message):
                raise ValueError(f"Invalid wazuh agent message from addr {addr}")

            pwd = parsed_message.get("password", None)

            if self.password and len(self.password) > 0:
                if not pwd:
                    raise ValueError(f"wazuh agent without password: {addr}")

                if not self.password == pwd:
                    raise ValueError(f"Invalid wazuh agent password: {addr}")

            elif pwd is not None:
                raise ValueError(f'wazuh agent trying to register with password but the server is not configured with one: {addr}')

            agent = self.add_new_agent(
                parsed_message.get("A", ""), parsed_message.get("V", "")
            )

            self._append_client_keys_line(agent)

            register_response = f"OSSEC K:'{agent.id:03d} {agent.name} any {agent.key.decode()}'".encode()

            logger.debug("Registration response: %s", register_response)

            writer.write(register_response)

            logger.info(f"New agent registered: {agent.id}:{agent.name}")

        except Exception as ex:
            logger.error(f"Exception at connection callback. {str(ex)}")
        finally:
            logger.info(f"Closing connection: {addr}")
            writer.close()

    async def _read_frame(self, reader: asyncio.StreamReader):
        data = await reader.readexactly(4)
        packet_size = int.from_bytes(data, "little")
        if packet_size == 0 or packet_size > 10 * 1024 * 1024:
            return None
        return await reader.readexactly(packet_size)

    def handle_control_message(
        self, msg: DecodedMessage, agent: WazuhAgent
    ) -> bytes | None:
        logger.debug("Received agent control message")
        event = msg.get_event()
        if event.startswith(WazuhRcEventBytes.SHUTDOWN):
            return None
        elif event.startswith(WazuhRcEventBytes.STARTUP):
            logger.info("Received agent startup. %s:%s", agent.id, agent.name)
        else:
            logger.debug("Probably keepalive: %s", event)
        return WazuhHelper.encodeSecMessage(agent, WazuhRcEventBytes.ACK)

    @staticmethod
    def _decode_and_validate(
        agent: WazuhAgent, aes_data: bytes
    ) -> tuple[DecodedMessage, bool]:
        msg = WazuhHelper.decodeSecMessage(agent, aes_data)
        return msg, msg.is_valid_checksum

    async def handle_log_message(
        self, msg: DecodedMessage, agent: WazuhAgent
    ) -> bytes | None:
        logger.debug(
            "Received agent log message: agent(%s): %s | %s",
            agent.id,
            agent.name,
            msg.get_event(),
        )
        if self.log:
            if self.buffer_queue:
                await self.buffer_queue.add_buffer(msg.get_event())

    # wazuh log server 1514
    async def _l_connection_callback(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):

        addr = writer.get_extra_info("peername")
        logger.info(f"Connection received: logging server {addr}")

        try:
            while True:
                try:
                    payload = await self._read_frame(reader)
                except asyncio.IncompleteReadError:
                    logger.info(f"Agent disconnected {addr}")
                    break
                if not payload:
                    logger.error("Invalid wazuh message")
                    break

                agent_id, aes_data = WazuhHelper.parseMessageHeader(payload)
                agent = self.getAgentId(agent_id)

                if agent is None:
                    logger.warning("Unknown agent id: %s", agent_id)
                    break

                if len(aes_data) > _OFFLOAD_THRESHOLD:
                    msg, checksum_ok = await asyncio.get_running_loop().run_in_executor(
                        self._executor, self._decode_and_validate, agent, aes_data
                    )
                else:
                    msg, checksum_ok = self._decode_and_validate(agent, aes_data)

                if not checksum_ok:
                    logger.error(
                        "Invalid message checksum. agent: %s, %s", agent_id, agent.name
                    )
                    break

                ret = None
                if msg.is_control_message():
                    ret = self.handle_control_message(msg, agent)
                else:
                    ret = await self.handle_log_message(msg, agent)
                if ret:
                    writer.write(ret)
                    await writer.drain()
        finally:
            logger.info(f"Connection closed: {addr}")
            writer.close()

    async def _start_registration_server(self):
        logging.debug(
            f"Starting registration server. host: {self.host}. port: {self.port_registration}. reuse port: {self.reuse_port}"
        )
        return await asyncio.start_server(
            self._r_connection_callback,
            self.host,
            self.port_registration,
            ssl=self.ssl,
            reuse_port=self.reuse_port,
        )

    async def _start_logging_server(self):
        logging.debug(
            f"Starting logging server. host: {self.host}. port: {self.port_logging}. reuse port: {self.reuse_port}"
        )
        return await asyncio.start_server(
            self._l_connection_callback,
            self.host,
            self.port_logging,
            ssl=None,
            reuse_port=self.reuse_port,
        )

    async def start(self):
        self.ssl = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl.load_cert_chain(self.ssl_cert, self.ssl_key)

        logger.info(
            f"Starting thread pool for message decoding. workers: {self.workers}"
        )
        # AES/zlib/md5 release the GIL, so threads give real parallelism here.
        self._executor = ThreadPoolExecutor(
            max_workers=self.workers, thread_name_prefix="decode"
        )
        if self.log is not None:
            await self.log.connect()

        logging.info(
            f"Starting server {self.host}:{self.port_registration},{self.port_logging}"
        )
        registration_server = await self._start_registration_server()
        logging_server = await self._start_logging_server()

        tasks = [registration_server.serve_forever(), logging_server.serve_forever()]
        if self.buffer_queue is not None:
            tasks.append(self.buffer_queue.flush_loop())

        async with registration_server, logging_server:
            await asyncio.gather(*tasks)
