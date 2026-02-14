import asyncio
import socket
import sys

sys.excepthook = lambda *args: None

async def handle_client(reader, writer):
    remote_reader = remote_writer = None
    try:
        # 1. 认证协商
        data = await reader.read(2)
        if not data or data[0] != 0x05:  # SOCKS5
            return
        nmethods = data[1]
        methods = await reader.read(nmethods)
        if not methods:
            return
        # 支持无认证
        writer.write(b"\x05\x00")
        await writer.drain()
        # 2. 获取请求
        data = await reader.read(4)
        if len(data) < 4:
            return
        ver, cmd, rsv, atyp = data
        if ver != 0x05 or cmd != 0x01:  # 仅支持 CONNECT
            return
        # 3. 解析目标地址
        if atyp == 0x01:  # IPv4
            ip_data = await reader.read(4)
            if len(ip_data) != 4:
                return
            addr = socket.inet_ntop(socket.AF_INET, ip_data)
        elif atyp == 0x03:  # 域名
            domain_len_data = await reader.read(1)
            if not domain_len_data:
                return
            domain_len = domain_len_data[0]
            addr = await reader.read(domain_len)
            if len(addr) != domain_len:
                return
        else:
            return
        port_data = await reader.read(2)
        if len(port_data) != 2:
            return
        port = int.from_bytes(port_data, 'big')
        # 4. 连接目标
        remote_reader, remote_writer = await asyncio.open_connection(addr, port)
        # 5. 返回成功响应 (BIND 地址设为全0)
        writer.write(b"\x05\x00\x00\x01" + b"\x00"*6)
        await writer.drain()
        # 6. 双向转发数据
        await asyncio.gather(
            copy_stream(reader, remote_writer),
            copy_stream(remote_reader, writer),
            return_exceptions=True  # 防止单个任务异常影响整体
        )
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        # 特定于连接断开的异常
        pass
    except Exception as e:
        # 其他异常静默处理
        pass
    finally:
        # 确保所有连接被关闭
        try:
            if remote_writer and not remote_writer.is_closing():
                remote_writer.close()
        except:
            pass
        try:
            if not writer.is_closing():
                writer.close()
        except:
            pass

async def copy_stream(src, dst):
    try:
        while True:
            data = await src.read(4096)
            if not data:
                break
            try:
                dst.write(data)
                await dst.drain()
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                # 写入失败时中断循环
                break
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    except Exception:
        pass
    finally:
        try:
            if not dst.is_closing():
                dst.close()
        except:
            pass

async def main():
    server = await asyncio.start_server(handle_client, '0.0.0.0', 1080)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except:
        pass


