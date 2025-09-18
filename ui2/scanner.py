from flask import Flask, request, jsonify
import subprocess
import re
import threading

app = Flask(__name__)

output_lines = []
process = None

def run_openssl_connect(host):
    global process
    cmd = [
        "openssl", "s_client",
        "-connect", host,
        "-servername", host.split(":")[0],
        "-ign_eof", "-state", "-msg"
    ]
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        output_lines.clear()

        def monitor():
            for line in process.stdout:
                output_lines.append(line)
                if "read R BLOCK" in line:
                    process.terminate()
                    break

        monitor_thread = threading.Thread(target=monitor)
        monitor_thread.start()
        monitor_thread.join(timeout=30)

        if monitor_thread.is_alive():
            process.kill()
            monitor_thread.join()

        output = ''.join(output_lines)
        if not output.strip():
            return None, "No output received"
        return output, None

    except Exception as e:
        return None, str(e)

def extract_ssl_details(output):
    cert_data = re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", output, re.DOTALL)
    subject = re.search(r"subject=([^\n\r]+)", output)
    issuer = re.search(r"issuer=([^\n\r]+)", output)
    verify_result = re.search(r"Verify return code: (\d+) \((.*?)\)", output)
    protocol = re.search(r"Protocol\s*:\s*(.*?)\n", output)
    cipher = re.search(r"Cipher\s*:\s*(.*?)\n", output)
    group = re.search(r"Negotiated TLS1\.3 group:\s*([^\n\r]+)", output) or re.search(r"Server Temp Key:\s*([^\n\r]+)", output)
    group = group.group(1).strip() if group else "Unknown"
    pkey_line = re.search(r"a:PKEY:\s*([A-Z0-9\-]+),\s*(\d+)\s*\(bit\);", output)
    if pkey_line:
        public_key = f"{pkey_line.group(2)} bit {pkey_line.group(1)}"
    else:
        pubkey = re.search(r"Server public key is\s+(\d+ bit)", output)
        if pubkey:
            peer_sig_type = re.search(r"Peer signature type:\s*([a-zA-Z0-9_]+)", output)
            algo = peer_sig_type.group(1).replace("_", "-") if peer_sig_type else "Unknown"
            public_key = f"{pubkey.group(1)} ({algo})"
        else:
            public_key = "Unknown"
    alpn = re.search(r"ALPN protocol:\s*(.*?)\n", output)
    resumed = re.search(r"(New|Reused), TLSv1\.3", output)
    signature_algo = re.search(r"sigalg:\s*(.*?)\n", output)
    return {
        "certificate": cert_data[0] if cert_data else None,
        "subject": subject.group(1).strip() if subject else "N/A",
        "issuer": issuer.group(1).strip() if issuer else "N/A",
        "verify_result": f"{verify_result.group(1)} ({verify_result.group(2)})" if verify_result else "?",
        "protocol": protocol.group(1).strip() if protocol else "Unknown",
        "cipher": cipher.group(1).strip() if cipher else "Unknown",
        "group": group,
        "public_key": public_key,
        "alpn": alpn.group(1).strip() if alpn else "None",
        "resumed": resumed.group(1) if resumed else "Unknown",
        "signature_algo": signature_algo.group(1).strip() if signature_algo else "Unknown",
    }

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    host = data.get("host")
    if not host:
        return jsonify({"error": "Missing host"}), 400

    output, error = run_openssl_connect(host)
    if error:
        return jsonify({"error": error})

    details = extract_ssl_details(output)
    return jsonify(details)

if __name__ == "__main__":
    app.run(debug=True)
