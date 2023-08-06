from enum import IntEnum
from typing import Generator, List, Optional
from contextlib import contextmanager
from ragger.backend import RaisePolicy
from ragger.backend.interface import BackendInterface, RAPDU
from ragger.bip import pack_derivation_path
import funcy


MAX_APDU_LEN: int = 255

CLA: int = 0xE0


class P1(IntEnum):
    # Parameter 1 for first APDU number.
    P1_START = 0x00
    # Parameter 1 for maximum APDU number.
    P1_MAX = 0x03
    # Parameter 1 for screen confirmation for GET_PUBLIC_KEY.
    P1_CONFIRM = 0x01


class P2(IntEnum):
    # Parameter 2 for last APDU to receive.
    P2_LAST = 0x00
    # Parameter 2 for more APDU to receive.
    P2_MORE = 0x80


class InsType(IntEnum):
    GET_VERSION = 0x03
    GET_APP_NAME = 0x04
    GET_PUBLIC_KEY = 0x05
    SIGN_EVENT = 0x07
    ENCRYPT = 0x08
    DECRYPT = 0x09
    GET_RESPONSE = 0xC0


class Errors(IntEnum):
    SW_DENY = 0x6985
    SW_WRONG_P1P2 = 0x6A86
    SW_WRONG_DATA_LENGTH = 0x6A87
    SW_INS_NOT_SUPPORTED = 0x6D00
    SW_CLA_NOT_SUPPORTED = 0x6E00
    SW_WRONG_RESPONSE_LENGTH = 0xB000
    SW_DISPLAY_ADDRESS_FAIL = 0xB002
    SW_MESSAGE_TOO_LONG = 0xB004
    SW_BAD_STATE = 0xB007
    SW_SIGNATURE_FAIL = 0xB008


def split_message(message: bytes, max_size: int) -> List[bytes]:
    return [message[x:x + max_size] for x in range(0, len(message), max_size)]


class BoilerplateCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend

    def get_app_and_version(self) -> RAPDU:
        return self.backend.exchange(cla=0xB0,  # specific CLA for BOLOS
                                     ins=0x01,  # specific INS for get_app_and_version
                                     p1=P1.P1_START,
                                     p2=P2.P2_LAST,
                                     data=b"")

    def get_version(self) -> RAPDU:
        return self.backend.exchange(cla=CLA,
                                     ins=InsType.GET_VERSION,
                                     p1=P1.P1_START,
                                     p2=P2.P2_LAST,
                                     data=b"")

    def get_app_name(self) -> RAPDU:
        return self.backend.exchange(cla=CLA,
                                     ins=InsType.GET_APP_NAME,
                                     p1=P1.P1_START,
                                     p2=P2.P2_LAST,
                                     data=b"")

    def get_public_key(self) -> RAPDU:
        return self.backend.exchange(cla=CLA,
                                     ins=InsType.GET_PUBLIC_KEY,
                                     p1=P1.P1_START,
                                     p2=P2.P2_LAST,
                                     data=b"")

    @contextmanager
    def get_public_key_with_confirmation(self) -> Generator[None, None, None]:
        with self.backend.exchange_async(cla=CLA,
                                         ins=InsType.GET_PUBLIC_KEY,
                                         p1=P1.P1_CONFIRM,
                                         p2=P2.P2_LAST,
                                         data=pack_derivation_path(b"")) as response:
            yield response

    @contextmanager
    def sign_event(self, hash: bytes) -> Generator[None, None, None]:
        with self.backend.exchange_async(cla=CLA,
                                         ins=InsType.SIGN_EVENT,
                                         p1=0x01,
                                         p2=0x00,
                                         data=hash) as response:
            yield response

    def encrypt(self, publickey: bytes, hash: bytes) -> bytes:
        arr: bytes = []
        self.backend.raise_policy = RaisePolicy.RAISE_NOTHING

        self.backend.exchange(cla=CLA,
                              ins=InsType.ENCRYPT,
                              p1=P1.P1_START,
                              p2=P2.P2_MORE,
                              data=publickey)

        p1 = 1
        chunks = list(funcy.chunks(128, hash))
        for chunk in chunks:
            latest = True if chunk == chunks[-1] else False
            response = self.backend.exchange(cla=CLA,
                                             ins=InsType.ENCRYPT,
                                             p1=p1,
                                             p2=P2.P2_LAST if latest else P2.P2_MORE,
                                             data=chunk)
            p1 += 1
            if response.status != 0x9000 and response.status != 0x6100:
                raise Exception("Encryption failed")
            if latest:
                arr += response.data
                while (response.status == 0x6100):
                    response = self.backend.exchange(cla=CLA,
                                                     ins=InsType.GET_RESPONSE,
                                                     p1=P1.P1_START,
                                                     p2=P2.P2_LAST)
                    arr += response.data
        return arr

    def decrypt(self, publickey: bytes, iv: bytes, hash: bytes) -> bytes:
        arr: bytes = []

        self.backend.exchange(cla=CLA,
                              ins=InsType.DECRYPT,
                              p1=P1.P1_START,
                              p2=P2.P2_MORE,
                              data=publickey)

        self.backend.exchange(cla=CLA,
                              ins=InsType.DECRYPT,
                              p1=1,
                              p2=P2.P2_MORE,
                              data=iv)

        p1 = 2
        chunks = list(funcy.chunks(128, hash))
        for chunk in chunks:
            latest = True if chunk == chunks[-1] else False
            response = self.backend.exchange(cla=CLA,
                                             ins=InsType.DECRYPT,
                                             p1=p1,
                                             p2=P2.P2_LAST if latest else P2.P2_MORE,
                                             data=chunk)
            p1 += 1
            if response.status != 0x9000 and response.status != 0x6100:
                raise Exception("Encryption failed")
            if latest:
                arr += response.data
                while (response.status == 0x6100):
                    response = self.backend.exchange(cla=CLA,
                                                     ins=InsType.GET_RESPONSE,
                                                     p1=P1.P1_START,
                                                     p2=P2.P2_LAST)
                    arr += response.data
        return arr

    def get_async_response(self) -> Optional[RAPDU]:
        return self.backend.last_async_response
