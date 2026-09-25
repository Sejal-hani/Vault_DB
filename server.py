import json
from http.server import HTTPServer, SimpleHTTPRequestHandler
from decimal import Decimal
from datetime import datetime
from vault_client import VaultClient

client = VaultClient()

def json_serial(obj):
    if isinstance(obj, (datetime,)):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return float(obj)
    return str(obj)

class SimpleHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            with open("index.html", "rb") as f:
                self.wfile.write(f.read())
        elif self.path == "/api/logs":
            logs = client.get_audit_logs(limit=15)
            log_list = []
            for r in logs:
                log_list.append({
                    "id": r[0],
                    "time": json_serial(r[1]),
                    "user": r[2],
                    "role": r[3],
                    "action": r[4],
                    "table": r[5],
                    "status": r[6],
                    "query": r[7] if len(r) > 7 else ""
                })
            data = json.dumps(log_list).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/execute":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            user = body.get("user", "alice@bank.com")
            query = body.get("query", "")

            try:
                res = client.execute(query, app_user=user)
                clean_res = [[json_serial(item) for item in row] for row in res] if res else []
                resp_data = {
                    "status": "SUCCESS",
                    "results": clean_res,
                    "rows_affected": getattr(client, "last_rows_affected", 0),
                    "columns": getattr(client, "last_columns", [])
                }
            except PermissionError as pe:
                resp_data = {"status": "DENIED", "error": str(pe)}
            except Exception as ex:
                resp_data = {"status": "ERROR", "error": str(ex)}

            data = json.dumps(resp_data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

def main():
    port = 8080
    server = HTTPServer(("127.0.0.1", port), SimpleHandler)
    print("=" * 60)
    print(f"VaultDB Dashboard running at http://localhost:{port}")
    print("Open the link above in your browser.")
    print("=" * 60)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        client.close()
        server.server_close()

if __name__ == "__main__":
    main()
