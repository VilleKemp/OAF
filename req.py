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
import re
import sys


class Url:
    def __init__(self, base, endpoint, parameter=''):
        self.base = base
        self.endpoint = endpoint
        self.parameter = parameter


class Req:
    # Bunch of values used in dummy value generation.
    integers = ["integer", "Integer", "int", "Int", "INT"]
    strings = ["string", "String", "STRING", "str"]
    rand_range = [0, 100]
    rand_string_length = 10

    def __init__(self, url, parameters, method, header=None, content=None, security=None):
        self.url = url
        self.parameters = parameters
        self.method = method
        self.header = header
        self.content = content
        self.security = security
        self.par_query = {}
        self.par_header = {}
        self.par_cookie = {}
        self.sec_query = {}
        self.sec_header = {}
        self.sec_cookie = {}

    def set_dummy_values(self):
        for par in self.parameters:
            '''
            If par.value is None generates either a random int or string
            
            '''
            # TODO Can't generate these randomly. Need to use same "corpus" for all requests!
            #  Otherwise certain gets won't work
            logging.debug("Url is {}.".format(self.url.base[0] + self.url.endpoint))
            logging.debug("     Parameter: {}".format(par.name))
            if par.value is None and par.options is None:
                # TODo does not support arrays
                # If format is int gives randint if it is string gives randstring. default to int
                if par.format_ in self.integers:
                    par.value = random.randint(self.rand_range[0], self.rand_range[1])
                elif par.format_ in self.strings:
                    par.value = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.rand_string_length))
                else:
                    par.value = random.randint(self.rand_range[0], self.rand_range[1])
                logging.debug("     Parameter had no previous value")
                logging.debug("     Parameters format is {}".format(par.format_))
                logging.debug("     Parameters was given value {}".format(par.value))
            elif isinstance(par.value, int) and par.options is None:
                logging.debug("     Parameter used to be {} with value {}".format(par.format_, par.value))
                par.value = random.randint(self.rand_range[0], self.rand_range[1])
                logging.debug("     Value was changed to {}".format(par.value))

            elif isinstance(par.value, str) and par.options is None:
                logging.debug("     Parameter used to be {} with value {}".format(par.format_, par.value))
                par.value = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.rand_string_length))
                logging.debug("     Value was changed to {}".format(par.value))
            elif par.options is not None:
                logging.debug("Par options was not None")
                par.value = random.choice(par.options)
            else:
                logging.error("Setting dummy values failed. Setting value to 42")
                par.value = 42

    def send(self, args):
        '''
        Sends the request based on its values.

        returns:
            response code + request object:
            False: send failed for some reason.

        '''
        # Requests library takes parameters as dict so we create one for each type

        logging.debug("Preparing to send")
        # Loop through all parameters
        for p in self.parameters:
            if p.location == "query":
                self.par_query[p.name] = p.value
            elif p.location == "cookie":
                self.par_cookie[p.name] = p.value
            elif p.location == "header":
                self.par_header[p.name] = p.value
            elif p.location == "path":
                # if location is path we add value to the end of url.endpoint
                self.url.parameter = p.value
                # Remove {par} from url
                self.url.endpoint = re.sub('{.*}', '', self.url.endpoint, flags=re.DOTALL)
            else:
                logging.error("Error parsing parameters. Location not found")
                return False, False
        # Security
        # TODO add support to other methods
        if self.security is not None:
            # Apikey security
            # logging.debug(self.security)
            # TODO security contains many objects. Find out if it is intentional
            for sec in self.security:
                # logging.debug(sec.type_)
                # logging.debug("{} {} {}".format(sec.type_, sec.name, sec.location))
                if sec.type_ == "apiKey":
                    if not args.apikey:
                        logging.error("Security type is {} but no apikey provided.".format(sec.type_))
                        sys.exit(0)
                    if sec.location == "query":
                        # TODO put these to another parameter so fuzzer doesnt touch them
                        self.sec_query[sec.name] = args.apikey
                    elif sec.location == "cookie":
                        self.sec_cookie[sec.name] = args.apikey
                    elif sec.location == "header":
                        self.sec_header[sec.name] = args.apikey
                    else:
                        logging.error("Security location is {}. It need to be query, cookie or header")
                        sys.exit(0)

                #else:
                    #logging.error("Security type {} provided".format(sec.type_))
                    #logging.error("Only apikey security is currently supported. Shutting down program")
                    #sys.exit(0)
        # TODO currently only uses first url

        r_url = ''.join((self.url.base[0], self.url.endpoint))
        logging.debug("\nSending {} to {}".format(self.method, r_url))
        logging.debug("Header params: {}\n Cookie params: {}\n Query params: {}\n Path params: {}".format(
            {**self.par_header, **self.sec_header}, {**self.par_cookie, **self.sec_cookie}, {**self.par_query, **self.sec_query}, self.url.parameter))
        if self.method == "GET":
            r = requests.get(''.join((r_url, str(self.url.parameter))),
                             headers={**self.par_header, **self.sec_header}, cookies={**self.par_cookie, **self.sec_cookie},
                             params={**self.par_query, **self.sec_query})

        elif self.method == "POST":
            r = requests.post(''.join((r_url, str(self.url.parameter))),
                             headers={**self.par_header, **self.sec_header}, cookies={**self.par_cookie, **self.sec_cookie},
                             params={**self.par_query, **self.sec_query})

        elif self.method == "DELETE":
            r = requests.delete(''.join((r_url, str(self.url.parameter))),
                             headers={**self.par_header, **self.sec_header}, cookies={**self.par_cookie, **self.sec_cookie},
                             params={**self.par_query, **self.sec_query})

        elif self.method == "PUT":
            r = requests.put(''.join((r_url, str(self.url.parameter))),
                             headers={**self.par_header, **self.sec_header}, cookies={**self.par_cookie, **self.sec_cookie},
                             params={**self.par_query, **self.sec_query})

        else:
            logging.error("Error sending request. Method not found")
            return False

        return r.status_code, r

