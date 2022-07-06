import json
import urllib.parse

import aiohttp
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
from fastapi import status, Response

from Qwangy.application import app


class AuthClient:
    def __init__(self):
        self.conf = None
        self.server = None
        self.realm = None
        self.client_id = None
        self.client_secret = None
        self.realm_url = None
        self.openid_url = None
        self.token_url = None

    def initialize(self):
        conf = app.config['auth']
        self.conf = conf
        self.server = conf['server']
        self.realm = conf['realm']
        self.client_id = conf['client_id']
        self.client_secret = conf['client_secret']
        self.realm_url = f"{conf['server']}realms/{conf['realm']}"
        self.openid_url = f"{self.realm_url}/protocol/openid-connect"
        self.token_url = f"{self.openid_url}/token"

    async def auth_login(self, login, password):
        async with aiohttp.ClientSession() as http:
            r = await http.post(
                self.token_url,
                data={
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'grant_type': 'password',
                    'username': login,
                    'password': password,
                },
                ssl=False)

        if 200 <= r.status < 300:
            rdata = await r.json()
            resp = JSONResponse(rdata)
            return resp
        elif r.status == status.HTTP_400_BAD_REQUEST:
            rdata = await r.json()
            if rdata.get('error') == 'invalid_grant':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST
                )
        elif r.status == status.HTTP_401_UNAUTHORIZED:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED
            )

        raise NotImplementedError(f'auth server: {r.status}, {await r.text()}')

    async def auth_refresh_token(self, refresh_token):
        async with aiohttp.ClientSession() as http:
            r = await http.post(
                self.token_url,
                data={
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'grant_type': 'refresh_token',
                    'refresh_token': refresh_token,
                },
                ssl=False)

        if 200 <= r.status < 300:
            rdata = await r.json()
            resp = JSONResponse(rdata)
            return resp
        elif (r.status in [
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN,
        ]):
            rtext = await r.text()
            resp = Response(
                status_code=r.status,
                content=rtext,
                headers=r.headers)
            return resp

        raise NotImplementedError(f'auth server: {r.status}, {await r.text()}')

    async def auth_logout(self, refresh_token):
        async with aiohttp.ClientSession() as http:
            r = await http.post(
                f'{self.openid_url}/logout',
                data={
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'refresh_token': refresh_token,
                },
                ssl=False)

            if r.status == status.HTTP_204_NO_CONTENT:
                return {'status_logaut': 'ok'}
            elif r.status == status.HTTP_400_BAD_REQUEST:
                rdata = await r.json()
                resp = JSONResponse(rdata)
                return resp

            raise NotImplementedError(f'auth server: {r.status}, {await r.text()}')

    async def get_userinfo(self, access_token):
        async with aiohttp.ClientSession() as http:
            url = f'{self.openid_url}/userinfo'
            resp = await http.get(
                url,
                headers={
                    'Authorization': 'Bearer %s' % access_token
                },
                ssl=False)

            if resp.status == status.HTTP_200_OK:
                resp_data = await resp.json()
                user_data = {
                    'id': resp_data['sub']
                }
                return user_data
            else:
                return None

    async def auth_introspect_token(self, access_token):
        async with aiohttp.ClientSession() as http:
            resp = await http.post(
                f'{self.token_url}/introspect',
                data={
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'token': access_token,
                },
                ssl=False)
            if resp.status == status.HTTP_200_OK:
                intro_data = await resp.json()
                return intro_data
            else:
                return None

    async def get_userinfo_detail(self, access_token):
        if not access_token:
            return None

        r = await self.auth_introspect_token(access_token)
        if r is None:
            return None

        userinfo = {  # ADD MORE ATTR!!!
            'id': r['sub'],
            'preferred_username': r['preferred_username'],
        }

        return userinfo

    async def register(self, regdata):
        async with aiohttp.ClientSession() as http:
            r = await http.post(
                self.token_url,
                data={
                    'client_id': self.conf['client_id'],
                    'client_secret': self.conf['client_secret'],
                    'grant_type': 'password',
                    'username': self.conf['admin']['username'],
                    'password': self.conf['admin']['password'],
                },
                ssl=False,
                raise_for_status=False)

            rdata = await r.json()
            admin_access_token = rdata['access_token']
            username = regdata['username']

            url = f"{self.server}admin/realms/{self.realm}/users"

            body = json.dumps(
                {'username': regdata['username'],
                 'email': regdata['email'],
                 'firstName': regdata['organization_name'],
                 'enabled': 'True'})

            r = await http.post(
                url,
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer %s' % admin_access_token,
                },
                data=body,
                ssl=False)

            if not (200 <= r.status < 300):
                if r.status == status.HTTP_400_BAD_REQUEST:
                    HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=await r.text())

                raise NotImplementedError(
                    f'auth server: {r.status}, {await r.text()}')

            url = (url
                   + '?' + urllib.parse.urlencode({'username': username}))
            r = await http.get(
                url,
                headers={
                    'Authorization': 'Bearer %s' % admin_access_token
                },
                ssl=False)
            userdata = (await r.json())[0]
            return userdata

    async def register_confirm_by_phone(self, phone_number, code):
        async with aiohttp.ClientSession() as http:
            url = f'{self.realm_url}/register/confirm-by-phone'
            r = await http.post(
                url,
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                data={
                    'phoneNumber': phone_number,
                    'code': code,
                },
                ssl=False)

            r.raise_for_status()


auth_client = AuthClient()
