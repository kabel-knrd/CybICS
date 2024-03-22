#!/usr/bin/env python3

import asyncio
import logging
import socket

from pathlib import Path
from asyncua import Server, ua
from asyncua.crypto.permission_rules import SimpleRoleRuleset
from asyncua.server.user_managers import CertificateUserManager
from asyncua.crypto.cert_gen import setup_self_signed_certificate
from asyncua.crypto.validator import CertificateValidator, CertificateValidatorOptions
from cryptography.x509.oid import ExtendedKeyUsageOID
from asyncua.crypto.truststore import TrustStore
from pymodbus.client import ModbusTcpClient

USE_TRUST_STORE = False

async def main():
    _logger = logging.getLogger(__name__)

    cert_base = Path(__file__).parent
    server_cert = Path(cert_base / "certificates/server-certificate-example.der")
    server_private_key = Path(cert_base / "certificates/server-private-key-example.pem")

    host_name = socket.gethostname()
    server_app_uri = f"myselfsignedserver@{host_name}"
    cert_user_manager = CertificateUserManager()
    await cert_user_manager.add_user("certificates/trusted/peer-certificate-example-1.der", name='test_user')

    # Connect to OpenPLC
    client = ModbusTcpClient(host="openplc",port=502)  # Create client object
    client.connect() # connect to device, reconnect automatically

    # setup the cybics opcua our server
    server = Server(user_manager=cert_user_manager)
    await server.init()
    server.set_endpoint("opc.tcp://0.0.0.0:4840/freeopcua/server/")
    await server.set_application_uri(server_app_uri)

    # set up the namespace
    uri = "http://opcua.cybics.github.io"
    idx = await server.register_namespace(uri)
    server.set_server_name("CybICS")
    server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt],
                               permission_ruleset=SimpleRoleRuleset())

    # Below is only required if the server should generate its own certificate,
    # It will renew also when the valid datetime range is out of range (on startup, no on runtime)
    await setup_self_signed_certificate(server_private_key,
                                        server_cert,
                                        server_app_uri,
                                        host_name,
                                        [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH],
                                        {
                                            'countryName': 'CN',
                                            'stateOrProvinceName': 'AState',
                                            'localityName': 'Foo',
                                            'organizationName': "Bar Ltd",
                                        })

    # load server certificate and private key. This enables endpoints
    # with signing and encryption.
    await server.load_certificate(str(server_cert))
    await server.load_private_key(str(server_private_key))

    if USE_TRUST_STORE:
        trust_store = TrustStore([Path(cert_base / "certificates/trusted/")], [])
        await trust_store.load()
        validator = CertificateValidator(options=CertificateValidatorOptions.TRUSTED_VALIDATION | CertificateValidatorOptions.PEER_CLIENT,
                                         trust_store = trust_store)
    else:
        validator = CertificateValidator(options=CertificateValidatorOptions.EXT_VALIDATION | CertificateValidatorOptions.PEER_CLIENT)
    server.set_certificate_validator(validator)

    # populating the cybics address space
    # server.nodes, contains links to very common nodes like objects and root
    myobj = await server.nodes.objects.add_object(idx, "MyObject_TEST")
    gstvar = await myobj.add_variable(idx, "GST", ua.UInt16(0))
    hptvar = await myobj.add_variable(idx, "HPT", ua.UInt16(0))
    systemSenvar = await myobj.add_variable(idx, "systemSen", ua.UInt16(0))
    boSenvar = await myobj.add_variable(idx, "boSen", ua.UInt16(0))
    stopvar = await myobj.add_variable(idx, "STOP", ua.UInt16(0))
    manualvar = await myobj.add_variable(idx, "manual", ua.UInt16(0))
    await server.nodes.objects.add_method(
        ua.NodeId("ServerMethod", idx),
        ua.QualifiedName("ServerMethod", idx),
        [ua.VariantType.Int64],
        [ua.VariantType.Int64],
    )
    _logger.info("Starting server!")
    async with server:
        while True:
            # read GST and HPT to the OpenPLC
            _logger.info("Reading from modbus")
            gst = client.read_holding_registers(1124)
            hpt = client.read_holding_registers(1126)
            systemSen = client.read_holding_registers(2)
            boSen = client.read_holding_registers(3)
            stop = client.read_holding_registers(1129)
            manual = client.read_holding_registers(1131)
            await gstvar.write_value(ua.UInt16(gst.registers[0]))
            await hptvar.write_value(ua.UInt16(hpt.registers[0]))
            await systemSenvar.write_value(ua.UInt16(systemSen.registers[0]))
            await boSenvar.write_value(ua.UInt16(boSen.registers[0]))
            await stopvar.write_value(ua.UInt16(stop.registers[0]))
            await manualvar.write_value(ua.UInt16(manual.registers[0]))
            await asyncio.sleep(1)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main(), debug=True)