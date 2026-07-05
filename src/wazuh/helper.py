import zlib
import hashlib
from functools import lru_cache
from random import randint
from typing import Literal
from Crypto.Util.Padding import pad
from .enum import WazuhRcEventBytes
from .agent import WazuhAgent
from Crypto.Cipher import AES

hardcoded_wazuh_iv = b"FEDCBA0987654321"  # https://github.com/wazuh/wazuh/blob/v4.14.5/src/os_crypto/aes/aes_op.c#L26
_aes_id_len = len(b"#AES:")


class DecodedMessage:
    m_checksum: str
    m_rand: bytes
    m_global: int
    m_local: int
    m_body: bytes
    m_event: bytes

    def __init__(self, decompressed_buffer: bytes):
        self.original_buffer = decompressed_buffer
        self.m_checksum = decompressed_buffer[:32].decode()
        self.m_body = decompressed_buffer[32:]
        splitted_buffer = decompressed_buffer[32:].split(b":", maxsplit=2)
        if len(splitted_buffer) != 3:
            raise ValueError("Malformed secure message (wrong key or corruption?)")
        if len(splitted_buffer[0]) != 15:
            raise ValueError("Invalid message: rand + global - message parse")
        if len(splitted_buffer[1]) != 4:
            raise ValueError('Invalid message: "local" - message parse')
        if len(splitted_buffer[2]) < 2:
            raise ValueError("Invalid message: empty body")

        self.m_rand = splitted_buffer[0][:5]
        self.m_global = int(splitted_buffer[0][5:15])
        self.m_local = int(splitted_buffer[1])
        self.m_event = splitted_buffer[2]

    def get_event(self) -> bytes:
        return self.m_event

    def is_valid_checksum(self):
        return hashlib.md5(self.m_body).hexdigest() == self.m_checksum

    def is_control_message(
        self,
    ):  # if the message is not from control message so is from logcollector
        return self.m_event.startswith(WazuhRcEventBytes.START_HEADER)


class WazuhHelper:
    @staticmethod
    def parseMessageHeader(msg: bytes) -> tuple[int, bytes]:
        """Parse `!<id>!#AES:<data>` in a single pass, returning (agent_id, aes_data)."""
        _start = msg.find(b"!")
        _end = msg.find(b"!", _start + 1)
        agent_id = int(msg[_start + 1 : _end])
        aes_data = msg[_end + 1 + _aes_id_len :]
        return agent_id, aes_data

    @staticmethod
    @lru_cache(maxsize=None)
    def _derive_aes_key(key: bytes) -> bytes:
        return hashlib.md5(key).hexdigest().encode()

    @staticmethod
    def _decode(agent: WazuhAgent, msg: bytes) -> bytes:
        aes_key = WazuhHelper._derive_aes_key(agent.key)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=hardcoded_wazuh_iv)
        return cipher.decrypt(msg)

    @staticmethod
    def _encode(agent: WazuhAgent, msg: bytes) -> bytes:
        aes_key = WazuhHelper._derive_aes_key(agent.key)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=hardcoded_wazuh_iv)
        return cipher.encrypt(msg)

    @staticmethod
    def aes_str(
        agent: WazuhAgent,
        msg: bytes,
        action: Literal["decode", "encode"] = "decode",
    ) -> bytes:
        match action:
            case "decode":
                return WazuhHelper._decode(agent, msg)
            case "encode":
                return WazuhHelper._encode(agent, msg)

    @staticmethod
    def decompress(msg: bytes) -> bytes:
        return zlib.decompress(msg)

    @staticmethod
    def compress(msg: bytes) -> bytes:
        return zlib.compress(msg)

    @staticmethod
    def decodeSecMessage(agent: WazuhAgent, aes_data: bytes) -> DecodedMessage:
        decrypted = WazuhHelper.aes_str(agent, aes_data)
        decrypted = decrypted.lstrip(b"!")  # remove ! padding from start of the string
        decompressed_data = WazuhHelper.decompress(decrypted)
        return DecodedMessage(decompressed_data)

    @staticmethod
    def encodeSecMessage(
        agent: WazuhAgent,
        event: bytes,
        include_id: bool = False,
        tcp_len_frame=True,
    ) -> bytes:
        tmp = ("%05d%010d:%04d:" % (randint(1, 65535), 0, 0)).encode() + event
        body = hashlib.md5(tmp).hexdigest().encode() + tmp
        comp = WazuhHelper.compress(body)
        comp_size = len(comp) + 1
        bfsize = (8 - (comp_size % 8)) % 8
        plain = b"!" * (bfsize + 1) + comp
        plain = pad(plain, 16)
        ciphertxt = WazuhHelper.aes_str(agent, plain, action="encode")
        payload = b"#AES:" + ciphertxt
        if include_id:
            payload = b"!%03d!" % agent.id + payload
        if tcp_len_frame:
            return WazuhHelper.encodedSecMessageTcpFrame(payload)
        return payload

    @staticmethod
    def encodedSecMessageTcpFrame(payload: bytes) -> bytes:
        return len(payload).to_bytes(4, "little") + payload
