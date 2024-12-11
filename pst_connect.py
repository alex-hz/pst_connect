# 20230413 手动创建 powerstore 性能采集程序,去除原有依赖，只做性能采集
# 调试，指定hostip
# 20240315 禁用SSL证书报错
# 调用方法  pst_fun = pst_connect.pst_connect(username,password,verify=False)
# 调用方法  res_data = pst_fun.request(http_method, lun_url, payload)

import json
import base64
#import socket
import requests
import logging
#from requests.exceptions import SSLError
#from requests.exceptions import ConnectionError
#from requests.exceptions import TooManyRedirects
#from requests.exceptions import Timeout
#from PyPowerStore.utils.exception import PowerStoreException
#from PyPowerStore.utils import constants, helpers


VALID_CODES = [200, 201, 202, 204, 206, 207]
TIMEOUT = 120.0

# 忽略SSL证书告警
logging.captureWarnings(True)

class pst_connect():
    """Client class for PowerStore"""
    def __init__(self, username, password, verify, application_type=None,
                 timeout=None, enable_log=False):
        """ Initializes Client Class

        :param username: array username
        :type username: str
        :param password: array password
        :type password: str
        :param verify: Whether the SSL cert will be verified
        :type verify: bool
        :param application_type: Application Type
        :type application_type: str
        :param timeout: (optional) How long to wait for the server to send data
                        before giving up
        :param enable_log: (optional) Whether to enable log or not
        :type enable_log: bool
        :type timeout: float
        """
        global LOG
        self.username = username
        self.password = password
        self.verify = verify
        #self.verify = False
        #self.application_type = application_type
        self.application_type = None
        """Setting default timeout"""
        #self.timeout = timeout if timeout else constants.TIMEOUT
        self.timeout = timeout if timeout else TIMEOUT
        #LOG = helpers.get_logger(__name__, enable_log=enable_log)

    def get_auth_token(self, host, headers):
        """ Logout the current session.

        :param host: IP of the host
        :type: str
        :param headers: The header for the https request
        :type: dict
        :return: Dict containing authentication attributes
        :rtype: dict
        """
        auth_tokens = {}
        credentials = base64.b64encode(
            "{username}:{password}".format(
                username=self.username, password=self.password).encode())
        headers.update({'authorization': "Basic " + credentials.decode()})
        #login_url = constants.LOGIN_SESSION.format(host)
        login_url = "https://" + host + "/api/rest/login_session"
        response = requests.request(
            "GET", login_url, headers=headers, verify=self.verify,
            timeout=self.timeout)
        if response:
            auth_tokens.update({'DELL-EMC-TOKEN': response.headers.get('DELL-EMC-TOKEN')})
            auth_tokens.update({'set-cookie': response.headers.get('set-cookie')})
        return auth_tokens

    def fetch_response(self, http_method, url, payload=None, querystring=None,
                       myrange=None):
        """ Fetch & return the response based on request parameters.

        :param http_method: HTTP Method
        :type http_method: str
        :param url: Service Endpoint
        :type url: str
        :param payload: (optional) Request payload
        :type payload: dict
        :param querystring: (optional) Request querystring
        :type querystring: dict
        :param myrange: (optional) element's offset & limit. e.g. 100-199
        :type myrange: str
        :return: Request's response.
        :rtype: requests.models.Response object
        """

        headers = {
            'Accept': "application/json",
            'Accept-Language': "en-US",
            'content-type': "application/json",
            'Application-Type': self.application_type
        }
        split_host = url.split('/')
        auth_headers = {}
        auth_headers = self.get_auth_token(split_host[2], headers)

        #if split_host[5] in ENGVIS_LIST:
        #    headers['DELL-VISIBILITY'] = 'internal'

        if auth_headers:
            headers.update(auth_headers)

        #print(auth_headers)
        #LOG.debug("Request's http_method: '%s' url: '%s' payload: '%s' "
        #          "querystring: '%s' myrange: '%s'"
        #          % (http_method, url, payload, querystring, myrange))
        if myrange:
            headers["Range"] = myrange

        if payload:
            response = requests.request(
                http_method, url, data=json.dumps(payload), headers=headers,
                verify=self.verify, timeout=self.timeout)
        elif querystring:
            response = requests.request(
                http_method, url, headers=headers, params=querystring,
                verify=self.verify, timeout=self.timeout)
        else:
            response = requests.request(
                http_method, url, headers=headers, verify=self.verify,
                timeout=self.timeout)
        self.logout_session(split_host[2], headers)
        return response

    def logout_session(self, host, headers):
        """ Logout the current session.

        :param host: IP of the host
        :type: str
        :param headers: The header for the https request
        :type: dict
        """

        #login_url = constants.LOGOUT_URL.format(host)
        login_url = 'https://10.112.6.115/api/rest/logout'
        requests.request("POST", login_url, headers=headers, verify=self.verify,
            data=None, timeout=self.timeout)

    def is_valid_response(self, response):
        """ Check whether response is valid or not

        :param response: Request's response.
        :type response: requests.models.Response
        :return: bool
        """
        if response.status_code in VALID_CODES:
            return True
        return(False)

    def request(self, http_method, url, payload=None, querystring=None,all_pages=None):
        """Method which serves requests to PowerStore.
        :param http_method: HTTP Method
        :type http_method: str
        :param url: Service Endpoint
        :type url: str
        :param payload: (optional) Request payload
        :type payload: dict
        :param querystring: (optional) Request querystring
        :type querystring: dict
        :param all_pages: (optional) Indicates whether to return all available
                          entities on the storage system
        :type all_pages: If not given default is None, else bool
        :return: Request's response.
        :rtype: dict or list of dict
        """
        response_json = None
        try:
            response = self.fetch_response(
                http_method, url, payload=payload, querystring=querystring)
            try:
                if self.is_valid_response(response):
                    response_json = None
                    if response.status_code != 204:
                        response_json = response.json()
                        #return(response_json)
            except:
                response_json = '{"status":"error"}'
                response_json["response_code"] = response.status_code
        except:
            response_json = '{"status":"error"}'
            response_json["response_code"] = "try_error"
            #response_json["response_code"] = response.status_code
        return(response_json)
