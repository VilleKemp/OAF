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
import model3 as model

class Url:
    def __init__(self, base, endpoint, parameter=''):
        self.base = base
        self.endpoint = endpoint
        self.parameter = parameter


class Req:
    # Bunch of values used in dummy value generation.
    # I wasn't hundred percent sure about all the ways different formats might be spelled so I created
    # these lists
    integers = ["integer", "Integer", "int", "Int", "INT"]
    strings = ["string", "String", "STRING", "str"]
    arrays = ["array", "Array", "ARRAY"]
    objects = ["object", "obj", "Object"]
    booleans = ["bool", "boolean", "Boolean"]
    rand_range = [0, 100]
    rand_string_length = 10

    def __init__(self, url, parameters, method, header=None, content=None, security=None):
        self.url = url
        self.parameters = parameters
        self.method = method
        # Header is mean for headers that are not security or parameter related.
        # Consider combining them
        if header is None:
            self.header = {}
        else:
            self.header = header
        # requestBody object
        self.content = content
        self.security = security
        self.par_query = {}
        self.par_header = {}
        self.par_cookie = {}
        self.sec_query = {}
        self.sec_header = {}
        self.sec_cookie = {}
        #self.requestBody = None

    def handle_object(self, param):

        for par in param.value:
            if par.format_ in self.integers and par.options is None:
                logging.debug("     Parameter used to be {} with value {}".format(par.format_, par.value))
                par.value = random.randint(self.rand_range[0], self.rand_range[1])
                logging.debug("     Value was changed to {}".format(par.value))
            elif par.format_ in self.strings and par.options is None:
                # elif isinstance(par.value, str) and par.options is None:
                logging.debug("     Parameter used to be {} with value {}".format(par.format_, par.value))
                par.value = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.rand_string_length))
                logging.debug("     Value was changed to {}".format(par.value))
            elif par.format_ in self.arrays:
                # Going with the assumption that there are no other parameter within the array
                # Parameter is in Parameter object form

                for innerpar in par.value:
                    logging.info("innerpar: {}".format(innerpar))
                    logging.info(innerpar.print_info())
                    if innerpar.options is not None:
                        # parameter has options
                        innerpar.value = random.choice(innerpar.options)
                    else:
                        # There are no options
                        if innerpar.format_ in self.strings:
                            par.value = ''.join(
                                random.choices(string.ascii_uppercase + string.digits, k=self.rand_string_length))
                        elif innerpar.format_ in self.integers:
                            par.value = random.randint(self.rand_range[0], self.rand_range[1])
            elif par.format_ in self.objects:
                logging.debug("Parameter is an object")
                self.handle_object(par)
            elif par.options is not None:
                logging.debug("Par options was not None and it wasn't an array")
                par.value = random.choice(par.options)
            else:
                logging.error("Setting dummy values failed. Setting value to 42")
                par.value = 42
        return

    def set_dummy_values(self):
        for par in self.parameters:
            '''
            If par.value is None generates either a random int or string
            
            '''
            # TODO Can't generate these randomly. Need to use same "corpus" for all requests!
            #  Otherwise certain gets won't work
            logging.debug("Url is {}.".format(self.url.base[0] + self.url.endpoint))
            logging.debug("     Parameter: {}".format(par.name))

            #elif isinstance(par.value, int) and par.options is None:
            if par.format_ in self.integers and par.options is None:
                logging.debug("     Parameter used to be {} with value {}".format(par.format_, par.value))
                par.value = random.randint(self.rand_range[0], self.rand_range[1])
                logging.debug("     Value was changed to {}".format(par.value))
            elif par.format_ in self.strings and par.options is None:
            #elif isinstance(par.value, str) and par.options is None:
                logging.debug("     Parameter used to be {} with value {}".format(par.format_, par.value))
                par.value = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.rand_string_length))
                logging.debug("     Value was changed to {}".format(par.value))
            elif par.format_ in self.arrays:
                # Going with the assumption that there are no other parameter within the array
                # Parameter is in Parameter object form
                innerpar = par.value
                logging.info("Parameter is object: {} {}".format(par, innerpar))
                logging.info("innerpar par: {}".format(innerpar))
                if innerpar.options is not None:
                    #parameter has options
                    logging.info("Changing {} to {}".format(innerpar.value, random.choice(innerpar.options)))
                    innerpar.value = random.choice(innerpar.options)
                else:
                    #There are no options
                    if innerpar.format_ in self.strings:
                        par.value = ''.join(
                            random.choices(string.ascii_uppercase + string.digits, k=self.rand_string_length))
                    elif innerpar.format_ in self.integers:
                        par.value = random.randint(self.rand_range[0], self.rand_range[1])
            elif par.format_ in self.objects:
                logging.debug("Parameter is an object")
                self.handle_object(par)
            elif par.options is not None:
                logging.debug("Par options was not None and it wasn't an array")
                par.value = random.choice(par.options)
            elif par.format_ in self.booleans:
                par.value = random.choice([True, False])
            else:
                logging.error("Setting dummy values failed.{} {} Setting value to 42".format(par.name, par.format_))
                par.value = 42

            # Todo do the same for requestBody
            logging.info("RequestBody: {} ".format(self.content))
        for o in self.content:
            logging.info("Processing requestbody {} {}".format(o, o.type_))
            for par in o.params:
                logging.info("Processing parameter {}".format(par.name))
                if par.format_ in self.integers and par.options is None:
                    logging.debug("     Parameter used to be {} with value {}".format(par.format_, par.value))
                    par.value = random.randint(self.rand_range[0], self.rand_range[1])
                    logging.debug("     Value was changed to {}".format(par.value))
                elif par.format_ in self.strings and par.options is None:
                    # elif isinstance(par.value, str) and par.options is None:
                    logging.debug("     Parameter used to be {} with value {}".format(par.format_, par.value))
                    par.value = ''.join(
                        random.choices(string.ascii_uppercase + string.digits, k=self.rand_string_length))
                    logging.debug("     Value was changed to {}".format(par.value))
                elif par.format_ in self.arrays:
                    # Going with the assumption that there are no other parameter within the array
                    # Parameter is in Parameter object form
                    for innerpar in par.value:
                        logging.info("innerpar: {}".format(innerpar))
                        logging.info(innerpar.print_info())
                        if innerpar.options is not None:
                            # parameter has options
                            innerpar.value = random.choice(innerpar.options)
                        elif innerpar.format_ in self.objects:
                            # Handle objects
                            self.handle_object(innerpar)
                        else:
                            # There are no options
                            if innerpar.format_ in self.strings:
                                par.value = ''.join(
                                    random.choices(string.ascii_uppercase + string.digits, k=self.rand_string_length))
                            elif innerpar.format_ in self.integers:
                                par.value = random.randint(self.rand_range[0], self.rand_range[1])
                elif par.format_ in self.objects:
                    logging.debug("Parameter is an object")
                    self.handle_object(par)
                elif par.options is not None:
                    logging.debug("Par options was not None and it wasn't an array")
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
            # Save the parameters to their appropriate places
            logging.debug("GREP: {}".format(type(p.value)))
            # Value is occasionally an Parameter object. Get the value from the object if this is the case.
            if isinstance(p.value, model.Parameter):
                logging.debug("Values is Parameter {}".format(p.value.value))
                val = p.value.value
            else:
                val = p.value
            if p.location == "query":
                self.par_query[p.name] = val
            elif p.location == "cookie":
                self.par_cookie[p.name] = val
            elif p.location == "header":
                self.par_header[p.name] = val
            elif p.location == "path":
                self.url.parameter = val
                # Remove {par} from url Dont do this here
                #self.url.endpoint = re.sub('{.*}', '', self.url.endpoint, flags=re.DOTALL)
            else:
                logging.error("Error parsing parameters. Location not found")
                return False, False
        # Security
        # TODO add support to other methods
        logging.info("Security {}".format(self.security))
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

        # RequestBody
        # Choose which requestBody to use if it exists
        # Todo FIRST VERSION ONLY SUPPORTS JSON! ADD XML LATER WHEN THE DEMO WORKS

        request_body = None
        if len(self.content) == 1:
            # This might cause unintended situations
            self.header["Content-Type"] = "application/json"
            request_body = self.content[0]
        elif self.content is not None:
            for r in self.content:
                if r.type_ == "application/json":
                    request_body = r
                    # This should be technically right.
                    # Alternative ways: Check header and x-* fields for headers
                    # Try without and after 415 (unsupported media type) do this
                    self.header["Content-Type"] = "application/json"
                    break
        if request_body is not None:
            request_body = request_body.json()





        # TODO currently only uses first url

        r_url = ''.join((self.url.base[0], self.url.endpoint))
        # Replace {par} with urlparameter
        if self.url.parameter is not None:
            r_url = re.sub('{.*}', str(self.url.parameter), r_url, flags=re.DOTALL)

        logging.debug("\nSending {} to {}".format(self.method, r_url))
        logging.debug("Header params: {}\n Cookie params: {}\n Query params: {}\n Path params: {}\n Content: {}".format(
            {**self.par_header, **self.sec_header, **self.header}, {**self.par_cookie, **self.sec_cookie}, {**self.par_query, **self.sec_query}, self.url.parameter, request_body))
        if self.method == "GET":
            r = requests.get(r_url,
                             headers={**self.par_header, **self.sec_header, **self.header}, cookies={**self.par_cookie, **self.sec_cookie},
                             params={**self.par_query, **self.sec_query}, data=request_body)

        elif self.method == "POST":
            r = requests.post(r_url,
                             headers={**self.par_header, **self.sec_header, **self.header}, cookies={**self.par_cookie, **self.sec_cookie},
                             params={**self.par_query, **self.sec_query}, data=request_body)

        elif self.method == "DELETE":
            r = requests.delete(r_url,
                             headers={**self.par_header, **self.sec_header, **self.header}, cookies={**self.par_cookie, **self.sec_cookie},
                             params={**self.par_query, **self.sec_query}, data=request_body)

        elif self.method == "PUT":
            r = requests.put(r_url,
                             headers={**self.par_header, **self.sec_header, **self.header}, cookies={**self.par_cookie, **self.sec_cookie},
                             params={**self.par_query, **self.sec_query}, data=request_body)

        else:
            logging.error("Error sending request. Method not found")
            return False

        return r.status_code, r

