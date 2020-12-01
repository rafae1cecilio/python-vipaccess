# -*- coding: utf-8 -*-
#
#   Copyright 2015 Forest Crossman
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


# Python 2/3 compatibility
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

from vipaccess.provision import *

from nose.tools import assert_equal, assert_true, assert_false, assert_is_none, assert_is_not_none
from time import sleep


def test_generate_request():
    expected = '<?xml version="1.0" encoding="UTF-8" ?>\n<GetSharedSecret Id="1412030064" Version="2.0"\n    xmlns="http://www.verisign.com/2006/08/vipservice"\n    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n    <TokenModel>SYMC</TokenModel>\n    <ActivationCode></ActivationCode>\n    <OtpAlgorithm type="HMAC-SHA1-TRUNC-6DIGITS"/>\n    <SharedSecretDeliveryMethod>HTTPS</SharedSecretDeliveryMethod>\n    <DeviceId>\n        <Manufacturer>Apple Inc.</Manufacturer>\n        <SerialNo>7QJR44Y54LK3</SerialNo>\n        <Model>MacBookPro10,1</Model>\n    </DeviceId>\n    <Extension extVersion="auth" xsi:type="vip:ProvisionInfoType"\n        xmlns:vip="http://www.verisign.com/2006/08/vipservice">\n        <AppHandle>iMac010200</AppHandle>\n        <ClientIDType>BOARDID</ClientIDType>\n        <ClientID>Mac-3E36319D3EA483BD</ClientID>\n        <DistChannel>Symantec</DistChannel>\n        <ClientInfo>\n            <os>MacBookPro10,1</os>\n            <platform>iMac</platform>\n        </ClientInfo>\n        <ClientTimestamp>1412030064</ClientTimestamp>\n        <Data>Y95GpBio35otwd2H/4TjrukR0AnG7VR/KJ7qxz5Y370=</Data>\n    </Extension>\n</GetSharedSecret>'
    params = {
        'timestamp': 1412030064,
        'token_model': 'SYMC',
        'otp_algorithm': 'HMAC-SHA1-TRUNC-6DIGITS',
        'shared_secret_delivery_method': 'HTTPS',
        'manufacturer': 'Apple Inc.',
        'serial': '7QJR44Y54LK3',
        'model': 'MacBookPro10,1',
        'app_handle': 'iMac010200',
        'client_id_type': 'BOARDID',
        'client_id': 'Mac-3E36319D3EA483BD',
        'dist_channel': 'Symantec',
        'platform': 'iMac',
        'os': 'MacBookPro10,1',
    }
    request = generate_request(**params)
    assert_equal(expected, request)

def test_get_token_from_response():
    test_response = b'<?xml version="1.0" encoding="UTF-8"?>\n<GetSharedSecretResponse RequestId="1412030064" Version="2.0" xmlns="http://www.verisign.com/2006/08/vipservice">\n  <Status>\n    <ReasonCode>0000</ReasonCode>\n    <StatusMessage>Success</StatusMessage>\n  </Status>\n  <SharedSecretDeliveryMethod>HTTPS</SharedSecretDeliveryMethod>\n  <SecretContainer Version="1.0">\n    <EncryptionMethod>\n      <PBESalt>u5lgf1Ek8WA0iiIwVkjy26j6pfk=</PBESalt>\n      <PBEIterationCount>50</PBEIterationCount>\n      <IV>Fsg1KafmAX80gUEDADijHw==</IV>\n    </EncryptionMethod>\n    <Device>\n      <Secret type="HOTP" Id="SYMC26070843">\n        <Issuer>OU = ID Protection Center, O = VeriSign, Inc.</Issuer>\n        <Usage otp="true">\n          <AI type="HMAC-SHA1-TRUNC-6DIGITS"/>\n          <TimeStep>30</TimeStep>\n          <Time>0</Time>\n          <ClockDrift>4</ClockDrift>\n        </Usage>\n        <FriendlyName>OU = ID Protection Center, O = VeriSign, Inc.</FriendlyName>\n        <Data>\n          <Cipher>ILBweOCEOoMBLJARzoeUIlu0+5m6b3khZljd5dozARk=</Cipher>\n          <Digest algorithm="HMAC-SHA1">MoaidW7XDzeTZJqhfRQCZEieARM=</Digest>\n        </Data>\n        <Expiry>2017-09-25T23:36:22.056Z</Expiry>\n      </Secret>\n    </Device>\n  </SecretContainer>\n  <UTCTimestamp>1412030065</UTCTimestamp>\n</GetSharedSecretResponse>'
    expected_token = {
        'salt': b'\xbb\x99`\x7fQ$\xf1`4\x8a"0VH\xf2\xdb\xa8\xfa\xa5\xf9',
        'iteration_count': 50,
        'iv': b'\x16\xc85)\xa7\xe6\x01\x7f4\x81A\x03\x008\xa3\x1f',
        'id': 'SYMC26070843',
        'cipher': b' \xb0px\xe0\x84:\x83\x01,\x90\x11\xce\x87\x94"[\xb4\xfb\x99\xbaoy!fX\xdd\xe5\xda3\x01\x19',
        'digest': b'2\x86\xa2un\xd7\x0f7\x93d\x9a\xa1}\x14\x02dH\x9e\x01\x13',
        'expiry': '2017-09-25T23:36:22.056Z',
        'period': 30,
        'algorithm': 'sha1',
        'digits': 6,
        'counter': None,
    }
    token = get_token_from_response(test_response)
    assert_is_not_none(token.pop('timeskew', None))
    assert_equal(expected_token, token)

def test_decrypt_key():
    test_iv = b'\x16\xc85)\xa7\xe6\x01\x7f4\x81A\x03\x008\xa3\x1f'
    test_cipher = b' \xb0px\xe0\x84:\x83\x01,\x90\x11\xce\x87\x94"[\xb4\xfb\x99\xbaoy!fX\xdd\xe5\xda3\x01\x19'
    expected_key = b'ZqeD\xd9wg]"\x12\x1f7\xc7v6"\xf0\x13\\i'
    decrypted_key = decrypt_key(test_iv, test_cipher)
    assert_equal(expected_key, decrypted_key)

def test_generate_totp_uri():
    test_token = {
        'salt': b'\xbb\x99`\x7fQ$\xf1`4\x8a"0VH\xf2\xdb\xa8\xfa\xa5\xf9',
        'iteration_count': 50,
        'iv': b'\x16\xc85)\xa7\xe6\x01\x7f4\x81A\x03\x008\xa3\x1f',
        'id': 'SYMC26070843',
        'cipher': b' \xb0px\xe0\x84:\x83\x01,\x90\x11\xce\x87\x94"[\xb4\xfb\x99\xbaoy!fX\xdd\xe5\xda3\x01\x19',
        'digest': b'2\x86\xa2un\xd7\x0f7\x93d\x9a\xa1}\x14\x02dH\x9e\x01\x13',
        'expiry': '2017-09-25T23:36:22.056Z',
        'counter': None,
        'period': 30,
        'algorithm': 'sha1',
        'digits': 6,
        'timeskew': 0,
    }
    test_secret = b'ZqeD\xd9wg]"\x12\x1f7\xc7v6"\xf0\x13\\i'
    expected_uri = urlparse.urlparse('otpauth://totp/VIP%20Access:SYMC26070843?secret=LJYWKRGZO5TV2IQSD434O5RWELYBGXDJ&issuer=Symantec&digits=6&algorithm=SHA1&period=30&image=https://vip.symantec.com/favicon.ico')
    generated_uri = urlparse.urlparse(generate_otp_uri(test_token, test_secret))
    assert_equal(expected_uri.scheme, generated_uri.scheme)
    assert_equal(expected_uri.netloc, generated_uri.netloc)
    assert_equal(expected_uri.path, generated_uri.path)
    assert_equal(urlparse.parse_qs(expected_uri.params), urlparse.parse_qs(generated_uri.params))
    assert_equal(urlparse.parse_qs(expected_uri.query), urlparse.parse_qs(generated_uri.query))

def test_generate_hotp_uri():
    test_token = {
        'salt': b'1\x92\xef\xb5\x99\xaf\xa9\xe3)\x17\xaf \x9b\xa5\x95j7\xe7\xa9+',
        'iteration_count': 50,
        'iv': b'Q\xf6I\xb3\xc9!\xfd3\xc64\x8ae\x83\x8d\x9c\xaf',
        'id': 'UBHE57586348',
        'cipher': b"!\x90)]e\x12\xe6\xcf\xa9\xd3\xa7\xaf\xdf\xb0\x89\x1f~\xe6\x17\xe7'\xd7pU\xcd>x\xf7\xc1\xc22\xe1"    ,
        'digest': b'\xc3sA\xe9\x02\\\xff\x02m\x1d\xb5i\x1a\xb7\xdc\x85&yl\xcd',
        'expiry': '2022-06-03T07:21:46.825Z',
        'period': None,
        'counter': 1,
        'algorithm': 'sha1',
        'digits': 6,
        'timeskew': 0,
    }
    test_secret = b'\x9a\x13\xcd2!\xad\xbd\x97R\xfcEE\xb6\x92e\xb4\x14\xb0\xfem'
    expected_uri = urlparse.urlparse('otpauth://hotp/VIP%20Access:UBHE57586348?digits=6&algorithm=SHA1&counter=1&issuer=Symantec&secret=TIJ42MRBVW6ZOUX4IVC3NETFWQKLB7TN&image=https://vip.symantec.com/favicon.ico')
    generated_uri = urlparse.urlparse(generate_otp_uri(test_token, test_secret))
    assert_equal(expected_uri.scheme, generated_uri.scheme)
    assert_equal(expected_uri.netloc, generated_uri.netloc)
    assert_equal(expected_uri.path, generated_uri.path)
    assert_equal(urlparse.parse_qs(expected_uri.params), urlparse.parse_qs(generated_uri.params))
    assert_equal(urlparse.parse_qs(expected_uri.query), urlparse.parse_qs(generated_uri.query))

def provision_valid_token(token_model, attr, not_attr, check_sync=False):
    test_request = generate_request(token_model=token_model)
    test_response = requests.post(PROVISIONING_URL, data=test_request)
    test_otp_token = get_token_from_response(test_response.content)
    assert_is_not_none(test_otp_token[attr])
    assert_is_none(test_otp_token[not_attr])
    assert test_otp_token['id'].startswith(token_model)
    test_token_secret = decrypt_key(test_otp_token['iv'], test_otp_token['cipher'])
    assert_true(check_token(test_otp_token, test_token_secret))
    if check_sync:
        if test_otp_token['period'] is not None:
            time.sleep(2 * test_otp_token['period'])
        assert_true(sync_token(test_otp_token, test_token_secret))

def test_check_token_models():
    # Only try syncing one TOTP token, because it requires a delay.
    # Can we parallelize away? (https://nose.readthedocs.io/en/latest/doc_tests/test_multiprocess/multiprocess.html
    sync = True
    for token_model in ('VSMT', 'VSST', 'SYMC', 'SYDC'):
        yield provision_valid_token, token_model, 'period', 'counter', sync
        sync = False

    for token_model in ('UBHE',):
        yield provision_valid_token, token_model, 'counter', 'period', True

def test_check_token_detects_invalid_token():
    test_token = {'id': 'SYMC26070843', 'period': 30}
    test_token_secret = b'ZqeD\xd9wg]"\x12\x1f7\xc7v6"\xf0\x13\\i'
    assert_false(check_token(test_token, test_token_secret))
