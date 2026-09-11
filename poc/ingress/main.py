"""Fixed TCP ingress from loopback-published ports into the isolated lab.

There is no CONNECT, URL, DNS, or destination selection supplied by a client.
This service holds no credentials and exposes no administrative API.
"""
import selectors
import socket
import socketserver
import threading

TARGETS = {
    5432: ('postgres',5432), 8200: ('vault',8200), 8445: ('identity-authority',8445),
    8000: ('control-api',8000), 8080: ('supervisor',8080), 8001: ('legacy-app',8001),
    8002: ('integrated-app',8002), 8444: ('spiffe-service',8444), 8003: ('spiffe-caller',8003),
}


class Forward(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            upstream = socket.create_connection(TARGETS[self.server.server_address[1]], timeout=5)
        except OSError:
            return
        with upstream, selectors.DefaultSelector() as events:
            self.request.setblocking(False)
            upstream.setblocking(False)
            events.register(self.request, selectors.EVENT_READ, upstream)
            events.register(upstream, selectors.EVENT_READ, self.request)
            while True:
                ready = events.select(timeout=120)
                if not ready:
                    return
                for key, _ in ready:
                    try:
                        data = key.fileobj.recv(65536)
                        if not data:
                            return
                        # Bound stalled peers; sendall handles partial TCP writes.
                        key.data.settimeout(5)
                        key.data.sendall(data)
                        key.data.setblocking(False)
                    except OSError:
                        return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == '__main__':
    servers = [Server(('0.0.0.0', port), Forward) for port in TARGETS]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Event().wait()
