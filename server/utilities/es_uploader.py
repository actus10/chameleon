import config
import requests


class elastic_upload():
    def __init__(self):
        self.username = config.username
        self.password = config.password
        self.url = config.base_url
        self.auth_url = config.auth_url

    def http_session(self):
        return requests.Session()

    def session_auth(self):
        session = self.http_session()
        session.auth = (self.username, self.password)
        auth = session.post(self.url + self.auth_url)
        return session

    def send(self, path, data):
        session = self.session_auth()
        # session.post(self.url + path, data=data)
        return session.post(self.url + path, json=data)
        # #


