'''
Req
    url
        base (taken from server object)
        endpoint (from path)
    parameters (copu of parameter object)
        name: parameter name
        location: query,header,path,cookie
        required: true/false
        value: fuzzable variable
    method (from path GET,PUT etc)
    headers dict? list?
    content (from requestbody and parameter?)
'''

import random
import string
import logging
import requests


class Url:
    def __init__(self, base, endpoint, parameter=None):
        self.base = base
        self.endpoint = endpoint
        self.parameter = parameter


class Req:
    # Bunch of values used in dummy value generation.
    integers = ["integer", "Integer", "int", "Int", "INT"]
    strings = ["string", "String", "STRING", "str"]
    rand_range = [0, 100]
    rand_string_length = 10

    def __init__(self, url, parameters, method, header=None, content=None):
        self.url = url
        self.parameters = parameters
        self.method = method
        self.header = header
        self.content = content

    def set_dummy_values(self):
        for par in self.parameters:
            '''
            If par.value is None generates either a random int or string
            
            '''
            # TODO Can't generate these randomly. Need to use same "corpus" for all requests! Otherwise certain gets won't work
            logging.debug("url is {}.\n par.value is {}.\npar.format is {}".format(self.url,par.value, par.format))
            if par.value is None:
                # TODo does not support arrays
                # If format is int gives randint if it is string gives randstring. default to int
                if par.format in self.integers:
                    par.value = random.randint(self.rand_range[0], self.rand_range[1])
                elif par.format in self.strings:
                    par.value = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.rand_string_length))
                else:
                    par.value = random.randint(self.rand_range[0], self.rand_range[1])
            elif isinstance(par.value, int):
                par.value = random.randint(self.rand_range[0], self.rand_range[1])

            elif isinstance(par.value, str):
                par.value = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.rand_string_length))
            else:
                logging.error("Setting dummy values failed. Setting value to 42")
                par.value = 42
            logging.debug("After loop par.value is {}".format(par.value))

    def send(self):
        '''
        Sends the request based on its values.

        returns:
            response code + request object:
            False: send failed for some reason.

        '''
        # Requests library takes parameters as dict so we create one for each type
        par_query = {}
        par_header = {}
        par_cookie = {}
        logging.debug("Preparing to send")
        # Loop through all parameters
        for p in self.parameters:
            if p.location == "query":
                par_query[p.name] = p.value
            elif p.location == "cookie":
                par_cookie[p.name] = p.value
            elif p.location == "header":
                par_header[p.name] = p.value
            elif p.location == "path":
                # if location is path we add value to the end of url.endpoint
                self.url.parameter = p.value
            else:
                logging.error("Error parsing parameters. Location not found")
                return False, False

        # TODO currently only uses first url
        r_url = ''.join((self.url.base[0], self.url.endpoint))
        logging.debug("\nSending {} to {}".format(self.method, r_url))
        if self.method == "GET":
            r = requests.get('/'.join((r_url, str(self.url.parameter))), headers = par_header, cookies = par_cookie, params = par_query)

        elif self.method == "POST":
            r = requests.post('/'.join((r_url, str(self.url.parameter))), headers=par_header, cookies=par_cookie, params=par_query)

        elif self.method == "DELETE":
            r = requests.delete('/'.join((r_url, str(self.url.parameter))), headers=par_header, cookies=par_cookie, params=par_query)

        elif self.method == "PUT":
            r = requests.put('/'.join((r_url, str(self.url.parameter))), headers=par_header, cookies=par_cookie, params=par_query)

        else:
            logging.error("Error sending request. Method not found")
            return False

        return r.status_code, r

