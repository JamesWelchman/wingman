from os import urandom

import wingman as wg


def test_encrypt():
    enc_key = urandom(32)
    data = b"hello world"
    enc_data = wg.encrypt(enc_key, data)
    assert data == wg.decrypt(enc_key, enc_data)
