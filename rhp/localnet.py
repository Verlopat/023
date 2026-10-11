"""Loopback TCP micro-test; measured socket costs separate from simulation."""
from __future__ import annotations
import asyncio
from hashlib import sha256
from time import perf_counter


async def loopback_roundtrip(peers:int=6,timeout:float=4.0):
    if not 2 <= peers <= 128:
        raise ValueError('peers outside local test range')
    packet=sha256(b'RHP:LOCAL:DEMO\0').hexdigest().encode()+b'\n'
    received=0
    async def handler(reader,writer):
        nonlocal received
        try:
            data=await asyncio.wait_for(reader.readline(),timeout)
            if data==packet:
                received+=1
                writer.write(b'ack\n')
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
    server=await asyncio.start_server(handler,'127.0.0.1',0)
    port=server.sockets[0].getsockname()[1]
    start=perf_counter()
    async def send_one():
        reader,writer=await asyncio.wait_for(asyncio.open_connection('127.0.0.1',port),timeout)
        try:
            writer.write(packet)
            await writer.drain()
            return await asyncio.wait_for(reader.readline(),timeout)==b'ack\n'
        finally:
            writer.close()
            await writer.wait_closed()
    try:
        async with server:
            acknowledgements=await asyncio.gather(*(send_one() for _ in range(peers)))
    finally:
        server.close()
        await server.wait_closed()
    return {'peers':peers,'received':received,'acknowledged':sum(acknowledgements),
            'elapsed_ms':(perf_counter()-start)*1000,
            'socket_payload_bytes':peers*(len(packet)+len(b'ack\n')),
            'note':'real loopback TCP micro-test, not a distributed Byzantine network'}
