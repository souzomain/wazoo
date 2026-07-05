import logging
import asyncio
from typing import Awaitable, Callable
from collections import deque

logger = logging.getLogger()


class BufferQueue:
    max_time: int  # max time in secconds to flush
    max_lines: int  # max lines after flush
    buffer: deque[bytes]

    def __init__(
        self,
        flush_func: Callable[[deque[bytes]], Awaitable[None]],
        max_time: int = 1,
        max_lines: int = -1,
    ) -> None:
        if max_time <= 0:
            raise ValueError("max_time needs to be >= 1")

        if max_time >= 30:
            logger.warning(
                "This value for max_time buffer flush is too big, are you sure?"
            )

        self.flush_f = flush_func
        self.max_time = max_time
        self.max_lines = max_lines
        self.buffer = deque()
        self.ignore_max_lines = max_lines <= 0
        self._lock = asyncio.Lock()
        self._last_flush_time: float = 0.0

    async def add_buffer(self, buffer: bytes):
        async with self._lock:
            self.buffer.append(buffer)
            should_flush = (
                not self.ignore_max_lines and len(self.buffer) >= self.max_lines
            )
        if should_flush:
            logger.debug("Buffer is full, flushing")
            await self.flush()

    async def flush_loop(self):
        loop = asyncio.get_running_loop()
        self._last_flush_time = loop.time()
        while True:
            remaining = self.max_time - (loop.time() - self._last_flush_time)
            if remaining > 0:
                await asyncio.sleep(remaining)
                continue
            try:
                await self.flush()
            except Exception as ex:
                logger.error(f"Error while flushing on schedule: {str(ex)}")

    async def flush(self):
        self._last_flush_time = asyncio.get_running_loop().time()

        async with self._lock:
            if not self.buffer:
                return
            pending = self.buffer
            self.buffer = deque()

        logger.debug("Flushing")
        try:
            await self.flush_f(pending)
        except Exception as ex:
            logger.error(f"Error while flusing {str(ex)}")
