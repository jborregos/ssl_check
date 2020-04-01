import socket
import ssl
import sslpsk
from Crypto.Cipher import AES
from hashlib import md5

identity_hex1 = "0142416f68626d6436614739314946523140d5bfdad5fc5904d5eb9d69b4a4438b5f73b54d0231246b6001e091aa57f84d48"
identity_hex2 = "0142416f68626d6436614739314946523140d5bfdad5fc5904d5eb9d69b4a4438b5f73b54d0231246b6001e091aa57f84d48"

hint1 = '1dHRsc2NjbHltbGx3eWh50000000000000000'.encode('utf-8')
hint2 = '1dHRsc2NjbHltbGx3eWh5oIdtdLy3jOCW+y5F'.encode('utf-8')


def psk(hint, identity):
    key = md5(hint[-16:]).digest()
    print("Key ", key.hex())
    iv = md5(bytes.fromhex(identity)[1:]).digest()
    print("IV ", iv.hex())
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ret = cipher.encrypt(bytes.fromhex(identity)[1:33])
    print("Psk ", ret.hex())
    return ret


PSKS = {hint1: psk(hint1, identity_hex1),
        hint2: psk(hint2, identity_hex2)}


def client(host, port, psk):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.connect((host, port))

    ssl_sock = sslpsk.wrap_socket(tcp_socket,
                                  ssl_version=ssl.PROTOCOL_TLSv1_2,
                                  ciphers='PSK-AES128-CBC-SHA256',
                                  psk=lambda hint_var: (psk[hint_var.encode('utf-8')], bytes.fromhex(identity_hex1)))

    msg = "ping"
    ssl_sock.sendall(msg.encode())
    msg = ssl_sock.recv(4).decode()
    print('Client received: %s' % msg)

    ssl_sock.shutdown(socket.SHUT_RDWR)
    ssl_sock.close()


def main():
    host = 'a3.tuyaeu.com'
    port = 443
    client(host, port, PSKS)


if __name__ == '__main__':
    main()
