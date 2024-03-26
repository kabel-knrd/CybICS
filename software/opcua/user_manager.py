import logging
from pathlib import Path
from typing import Union

from asyncua.crypto import uacrypto
from asyncua.server.users import User, UserRole

admin_db =  {
#                "admin1": "adminpw1"
            }

users_db =  {
                "user1": "pw1"
            }

class Pw_Cert_UserManager:
    """
    Certificate user manager, takes a certificate or username/password handler with its associated users and provides those users.
    """
    def __init__(self):
        self._trusted_certificates = {}

    def get_user(self, iserver, username=None, password=None, certificate=None):
        if username in users_db and password == users_db[username]:
            return User(role=UserRole.User)
        if username in admin_db and password == admin_db[username]:
            return User(role=UserRole.Admin)
        if certificate is None:
            return None
        correct_users = [prospective_certificate['user'] for prospective_certificate in self._trusted_certificates.values()
                         if certificate == prospective_certificate['certificate']]
        if len(correct_users) == 0:
            return None
        else:
            return correct_users[0]

    async def add_role(self, certificate_path: Path, user_role: UserRole, name: str, format: Union[str, None] = None):
        certificate = await uacrypto.load_certificate(certificate_path, format)
        if name is None:
            raise KeyError

        user = User(role=user_role, name=name)

        if name in self._trusted_certificates:
            logging.warning("certificate with name %s "
                            "attempted to be added multiple times, only the last version will be kept.", name)
        self._trusted_certificates[name] = {'certificate': uacrypto.der_from_x509(certificate), 'user': user}

    async def add_user(self, certificate_path: Path, name: str, format: Union[str, None] = None):
        await self.add_role(certificate_path=certificate_path, user_role=UserRole.User, name=name, format=format)

    async def add_admin(self, certificate_path: Path, name: str, format: Union[str, None] = None):
        await self.add_role(certificate_path=certificate_path, user_role=UserRole.Admin, name=name, format=format)
