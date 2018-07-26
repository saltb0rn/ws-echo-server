#! /usr/bin/env python3
import argparse
import base64
import hashlib
import socketserver
import struct

MAGIC_STRING = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

RSP_TO_BAD_REQ = (
    b"HTTP/1.1 400 Bad Request\r\n"
    b"Content-Type: text/plain\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"Incorrect request"
)

RSP_TO_COMPLETE_HANDSHAKE = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"Sec-WebSocket-Accept: %s\r\n\r\n")


class EchoRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        """
        The plan:
            1. handshake
            2. if handshake successfully, then start to swap message,
               to swap message, do it in two parts: extract payload
               and send message back.
            3. if handshake failed, tell client that "Bad Request"
        """
        is_handshake_completed = self.handshake()
        if is_handshake_completed:
            while True:
                (
                    fin_and_opcode,
                    payload_len_indicator,
                    payload_len,
                    decoded_payload
                ) = self.extract_payload(self.request.recv(1024).strip())
                self.send_back(fin_and_opcode, payload_len_indicator,
                               payload_len, decoded_payload)

    def handshake(self):
        """
        The plan:
            1. handshake with HTTP GET request
            2. only consider "Connection", "Upgrade" and "Sec-WebSocket-Key"
               headers in this example.
            3. calculate Sec-WebSocket-Accept to send to the client
            4. return True for successful or False for failed to determine
               whether to swap data
        """
        _headers = self.request.recv(1024).strip().split(b"\r\n")
        headers = {}
        for h in _headers:
            try:
                key, value = h.split(b":")
            except ValueError:
                # ignore lines like "GET / HTTP/1.1"
                continue
            headers[key.strip(b" ")] = value.strip(b" ")
        if headers.get(b"Connection") == b"Upgrade" and \
           headers.get(b"Upgrade") == b"websocket":
            sec_websocket_key = headers.get(b"Sec-WebSocket-Key")
            if not sec_websocket_key:
                return False
            # to calcuate Sec-WebSocket-Accept
            sec_websocket_key += MAGIC_STRING
            sec_websocket_key = base64.standard_b64encode(
                hashlib.sha1(sec_websocket_key).digest())
            # no problem now, then complete the handshake
            self.request.sendall(
                RSP_TO_COMPLETE_HANDSHAKE % sec_websocket_key)
            # staring to swap data and to decode the frame
            return True
        else:
            self.request.sendall(RSP_TO_BAD_REQ)
            return False

    def extract_payload(self, frame):
        """
        One thing important is: the frame from the client is
        a bytes or bytearray and every byte equals to 8 bits.
        When we begin to extract fields from frame, this thing
        and data frame format will be the key to let us understand
        how to decode frame.

        When decoding, we need to think about what we will need to
        construct a frame to send back.

        The fields we will need to construct a frame are FIN and opcode,
        payload len, decoded payload and payload len indicator which tells
        us how to get payload len.

        Once we knew that, it is time to decode frame.
        """
        # the first byte stores FIN field and opcode field.
        # the second byte stores MASK field and payload_len indicator
        fin_and_opcode = frame[0]
        payload_len_indicator = frame[1] - 128
        # extract payload_len according to payload_len_indicator
        if payload_len_indicator <= 125:
            # the frame use 7 bits to store payload_len
            payload_len = payload_len_indicator
            mask_key = frame[2:6]
            mask_key_end = 6
        elif payload_len_indicator == 126:
            # the frames use 2 bytes to store payload_len
            payload_len = struct.unpack_from("!H", frame[2:4])[0]
            mask_key = frame[4:8]
            mask_key_end = 8
        else:
            # the frame uses 8 bytes to store payload_len
            payload_len = struct.unpack_from("!Q", frame[2:10])[0]
            mask_key = frame[10:14]
            mask_key_end = 14
        encrypted_payload = frame[
            mask_key_end: mask_key_end+payload_len]
        decoded_payload = bytearray(
            [
                encrypted_payload[i] ^ mask_key[i % 4]
                for i in range(payload_len)
            ])
        return (fin_and_opcode, payload_len_indicator,
                payload_len, decoded_payload)

    def send_back(self, fin_and_opcode, payload_len_indicator,
                  payload_len, decoded_payload):
        """
        To send back, we need to learn 3 things:
        1. the frame to send back whose mask field won't be set to 1;
        2. not consider the situation that message fragmentation here
        3. how to construct a frame manually
        """
        decoded_payload = decoded_payload
        if payload_len_indicator <= 125:
            # when payload_len_indicator <= 125,
            # the length of payload is payload_len_indicator
            frame = bytearray(
                [fin_and_opcode, payload_len]) + decoded_payload
        elif payload_len_indicator == 126:
            # unlike that the payload_len_indicator <= 125,
            # in this case, it is necessary to store payload_len
            # in other bytes, as well as payload_len_indicator is 127
            frame = bytearray(
                [fin_and_opcode, payload_len_indicator]) + \
                struct.pack("!H", payload_len) + decoded_payload
        else:
            frame = bytearray(
                [fin_and_opcode, payload_len_indicator]) + \
                struct.pack("!Q", payload_len) + decoded_payload
        self.request.sendall(frame)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Kick off a echo websocket server")
    parser.add_argument('host', help='IP or hostname')
    parser.add_argument('-p', help='Port (default=8001)',
                        metavar='port', type=int, default=8001)
    args = parser.parse_args()
    HOST, PORT = args.host, args.p
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer((HOST, PORT), EchoRequestHandler)
    server.serve_forever()
