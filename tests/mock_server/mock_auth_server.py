import socket
import json
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler


class MyHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve a JSON file named after the path
        json_file_path = self.path.lstrip('/')  # Remove leading slash for correct file path
        if json_file_path:  # Check if there is a filename in the path
            file_path = os.path.join(os.path.dirname(__file__), json_file_path + '.json')
            if os.path.isfile(file_path):
                with open(file_path, 'r') as file:
                    try:
                        data = json.load(file)
                        self.send_response(data['response_code'])
                        response_body = json.dumps(data['body']).encode('utf-8')
                        self.send_header('Content-Type', 'application/json')
                        self.send_header('Content-Length', str(len(response_body)))
                        for header, value in data['headers'].items():
                            self.send_header(header, value)
                        self.end_headers()
                        self.wfile.write(response_body)
                    except json.JSONDecodeError:
                        self.send_error(500, "Json Decode Error")
                    except KeyError as e:
                        self.send_error(500, f"Malformed JSON structure: missing {str(e)}")
                    return
        self.send_error(404, "File not found")



# Creating an ipv6 server listens to both ipv4 and ipv6 addresses
class HTTPServerV6(HTTPServer):
    address_family = socket.AF_INET


def main():
    server = HTTPServerV6(('0.0.0.0', 8080), MyHandler)
    server.serve_forever()


if __name__ == '__main__':
    main()
