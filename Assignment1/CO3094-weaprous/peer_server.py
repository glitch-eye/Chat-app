# Example usage
import json
from daemon import *
import argparse

PORT = 8000

app = WeApRous()




if __name__ == "__main__":
    # Parse command-line arguments to configure server IP and port
    parser = argparse.ArgumentParser(prog='Backend', description='', epilog='Beckend daemon')
    parser.add_argument('--server-ip', default='0.0.0.0')
    parser.add_argument('--server-port', type=int, default=PORT)
 
    args = parser.parse_args()
    ip = args.server_ip
    port = args.server_port
    # Prepare and launch the RESTful application
    app.prepare_address(ip, port)
    app.run()