from application_client.boilerplate_transaction import Transaction
from application_client.boilerplate_command_sender import BoilerplateCommandSender, Errors
from application_client.boilerplate_response_unpacker import unpack_get_public_key_response, unpack_sign_tx_response, unpack_sign_event_response
from ragger.backend import RaisePolicy
from ragger.navigator import NavInsID
from utils import ROOT_SCREENSHOT_PATH, check_signature_validity


def test_encrypt_decrypt(firmware, backend, navigator, test_name):

    text = "H"

    client = BoilerplateCommandSender(backend)
    response = client.encrypt(publickey=bytes.fromhex("e6c3340cf1385c48dd1967c28b70234e7528245b3c089a601b3e42176ef7d1604dbac701e7e5c8a37f26c3ff73e6feadf75017942a2f43c86ab6f4aaa41c8672"),
                              hash=text.encode())

    # Cyphered data size (big endian)
    # assert bytes(response[0:4]) == bytes.fromhex("20000000")
    assert response[4] == 16

    iv = bytes(response[5:21])
    cyphered_data = bytes(response[21:])

    response = client.decrypt(publickey=bytes.fromhex("e6c3340cf1385c48dd1967c28b70234e7528245b3c089a601b3e42176ef7d1604dbac701e7e5c8a37f26c3ff73e6feadf75017942a2f43c86ab6f4aaa41c8672"),
                              iv=iv,
                              hash=cyphered_data)

    # assert bytes(response[0:4]) == bytes.fromhex("20000000")
    uncyphered_data = bytes(response[4:])
    assert uncyphered_data.decode().strip('\x00') == text
