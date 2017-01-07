#!/usr/bin/env python
"""
This was taken, and modified from python-fitbit/gather_keys_oauth2.py,
License reproduced below.

--------------------------
Copyright 2012-2015 ORCAS

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

import os
import sys
import threading
import traceback
import webbrowser
import json
import argparse

from base64 import b64encode
import cherrypy
from fitbit.api import FitbitOauth2Client
from oauthlib.oauth2.rfc6749.errors import MismatchingStateError, MissingTokenError
from requests_oauthlib import OAuth2Session


class OAuth2Server:
    def __init__(self, client_id, client_secret,
                 redirect_uri='http://localhost:8080/'):
        """ Initialize the FitbitOauth2Client """
        self.redirect_uri = redirect_uri
        self.success_html = """
            <h1>You are now authorized to access the Fitbit API!</h1>
            <br/><h3>You can close this window</h3>"""
        self.failure_html = """
            <h1>ERROR: %s</h1><br/><h3>You can close this window</h3>%s"""
        self.oauth = FitbitOauth2Client(client_id, client_secret)

    def browser_authorize(self):
        """
        Open a browser to the authorization url and spool up a CherryPy
        server to accept the response
        """
        url, _ = self.oauth.authorize_token_url(redirect_uri=self.redirect_uri)
        # Open the web browser in a new thread for command-line browser support
        threading.Timer(1, webbrowser.open, args=(url,)).start()
        cherrypy.quickstart(self)

    def headless_authorize(self):
        """
        Display the authorization url for the user to copy and paste into
        a local browser
        """

        url, _ = self.oauth.authorize_token_url(redirect_uri=self.redirect_uri)

        print("Paste the following URL into a local browser, you'll be asked access")
        print("to your Fitbit health data and be redirected to a http://localhost")
        print("URL that will throw an error")
        print(url)

        code = input("Paste code argument from redirected URL: ")

        if code:
            try:
                self.oauth.fetch_access_token(code, self.redirect_uri)
            except MissingTokenError:
                print("Missing access token parameter. Check your client_secret parameter")
            except MismatchingStateError:
                print("CSRF Warning! Mismatching state")
        else:
            print("No access code given")

    @cherrypy.expose
    def index(self, state, code=None, error=None):
        """
        Receive a Fitbit response containing a verification code. Use the code
        to fetch the access_token.
        """
        error = None
        if code:
            try:
                self.oauth.fetch_access_token(code, self.redirect_uri)
            except MissingTokenError:
                error = self._fmt_failure(
                    'Missing access token parameter.</br>Please check that '
                    'you are using the correct client_secret')
            except MismatchingStateError:
                error = self._fmt_failure('CSRF Warning! Mismatching state')
        else:
            error = self._fmt_failure('Unknown error while authenticating')
        # Use a thread to shutdown cherrypy so we can return HTML first
        self._shutdown_cherrypy()
        return error if error else self.success_html

    def _fmt_failure(self, message):
        tb = traceback.format_tb(sys.exc_info()[2])
        tb_html = '<pre>%s</pre>' % ('\n'.join(tb)) if tb else ''
        return self.failure_html % (message, tb_html)

    def _shutdown_cherrypy(self):
        """ Shutdown cherrypy in one second, if it's running """
        if cherrypy.engine.state == cherrypy.engine.states.STARTED:
            threading.Timer(1, cherrypy.engine.exit).start()

def main():
    parser = argparse.ArgumentParser(description='Authenticate your Fitbit App.')
    parser.add_argument('client_id', help='The Client ID of your Fitbit App')
    parser.add_argument('client_secret', help='The Client Secret of your Fitbit App')
    parser.add_argument('--headless', action='store_true')

    args = parser.parse_args()
    server = OAuth2Server(args.client_id, args.client_secret)

    if args.headless:
        server.headless_authorize()
    else:
        server.browser_authorize()

    credentials = dict(
        client_id=args.client_id,
        client_secret=args.client_secret,
        access_token=server.oauth.token['access_token'],
        refresh_token=server.oauth.token['refresh_token'])
        
    json.dump(credentials, open('fitbit.json', 'w'))

if __name__ == '__main__':
    main()
