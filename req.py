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
import requests_oauthlib

import re
import sys
import model3 as model
import datetime

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
    # location for the dummy value
    DUMMY_FILE = 'seed/dummy'
    # Sets requests allow_redirects parameters value
    ALLOW_REDIRECTS = False

    def __init__(self, url, parameters, method, header=None, content=None, security=None, responses=None):
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
        self.responses = responses
        self.par_query = {}
        self.par_header = {}
        self.par_cookie = {}
        self.sec_query = {}
        self.sec_header = {}
        self.sec_cookie = {}
        # Contains uploaded files
        self.files = {}
        #self.requestBody = None

    def handle_object(self, param):

        for par in param.value:
            self.change_pars(par)
            '''
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
                logging.error("Setting dummy values failed. Parameter was {} \r\nSetting value to 42".format(par.name))
                par.value = 42
            '''
        return

    def set_dummy_values(self):
        for par in self.parameters:
            self.change_pars(par)
            '''
            If par.value is None generates either a random int or string
            
            
            logging.debug("Url is {}.".format(self.url.base[0] + self.url.endpoint))
            logging.debug("     Parameter: {}".format(par.name))

            # Integers
            if par.format_ in self.integers and par.options is None:
                logging.debug("     Parameter used to be {} with value {}".format(par.format_, par.value))
                par.value = random.randint(self.rand_range[0], self.rand_range[1])
                logging.debug("     Value was changed to {}".format(par.value))
            # Strings
            elif par.format_ in self.strings and par.options is None:
            #elif isinstance(par.value, str) and par.options is None:
                logging.debug("     Parameter used to be {} with value {}".format(par.format_, par.value))
                par.value = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.rand_string_length))
                logging.debug("     Value was changed to {}".format(par.value))
            # Arrays
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
            # Objects
            elif par.format_ in self.objects:
                logging.debug("Parameter is an object")
                self.handle_object(par)
            # Parameter that can only have specific options
            elif par.options is not None:
                logging.debug("Par options was not None and it wasn't an array")
                par.value = random.choice(par.options)
            # Booleans
            elif par.format_ in self.booleans:
                par.value = random.choice([True, False])
            # Everything else
            else:
                logging.error("Setting dummy values failed. Parameter was {} \r\nSetting value to 42".format(par.name))
                par.value = 42
            '''

            logging.info("RequestBody: {} ".format(self.content))
        for o in self.content:
            logging.info("Processing requestbody {} {}".format(o, o.type_))
            for par in o.params:
                self.change_pars(par)
                '''
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
                    logging.error(
                        "Setting dummy values failed. Parameter was {} \r\nSetting value to 42".format(par.name))
                    par.value = 42
                    '''

# TODO Refactoring. Remove above comments when everything works
    def change_pars(self, par):
        try:
            logging.info("Processing parameter {}".format(par.name))
            if par.format_ in self.integers and par.options is None:
                logging.debug("     Parameter used to be {} with value {}".format(par.format_, par.value))
                # TODO utilize format_detailed
                par.value = random.randint(self.rand_range[0], self.rand_range[1])
                logging.debug("     Value was changed to {}".format(par.value))
            elif par.format_ in self.strings and par.options is None:
                '''
                Create cases where string must abide to a specific format or similar to here.
                '''
                logging.debug("     Parameter used to be {} with value {}".format(par.format_, par.value))
                if par.format_detailed == "date" or par.format_detailed == "date-time":
                    # If the parameter should be in date/date-time format we give it current time
                    par.value = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                elif par.format_detailed == "binary":
                    # Api expects a file
                    par.value = par.name
                    if par.name not in self.files:
                        # Add dummy file to self.files
                        self.files[par.name] = open(self.DUMMY_FILE, 'rb')
                else:
                    # If above ifs don't happen we create a random string
                    par.value = ''.join(
                        random.choices(string.ascii_uppercase + string.digits, k=self.rand_string_length))
                logging.debug("     Value was changed to {}".format(par.value))
            elif par.format_ in self.arrays:
                try:
                    for innerpar in par.value:
                        self.change_pars(innerpar)
                except TypeError:
                    # Happens when there is only one object in array
                    self.change_pars(par.value)
            elif par.format_ in self.objects:
                logging.debug("Parameter is an object")
                for innerpar in par.value:
                    self.change_pars(innerpar)
                #self.handle_object(par)
            elif par.options is not None:
                logging.debug("Par options was not None and it wasn't an array")
                par.value = random.choice(par.options)
                # Booleans
            elif par.format_ in self.booleans:
                par.value = random.choice([True, False])
            else:
                logging.error(
                    "Setting dummy values failed. Parameter was {} \r\nSetting value to 42".format(par.name))
                par.value = 42
        except AttributeError:
            return
        return

    def connect_oauth(self, sec):
        '''
        Creates an oauth session based on the information found in the sec object

        :param sec:
        :return:
        '''
        # TODO add support for more oauth flows
        # TODO implicit doesn't seem to work. Need to check if the issues is with petshop or with the implementation
        # Implicit flow. Only using required parameters
        scope = []
        if sec.type_ == "oauth2" and sec.flows.get("implicit") is not None:
            try:
                for s, value in sec.flows.get("implicit").get("scopes").items():
                    scope.append(s)
                auth_url = sec.flows.get("implicit").get("authorizationUrl")
            except TypeError:
                logging.exception("Scopes likely missing")
                return None
            except KeyError:
                logging.exception("authorizationUrl likely missing")
                return None
            logging.info("oauth2 implicit flow")
            logging.info(auth_url)
            # TODO this part crashes if auth_url isn't using https
            oauth = requests_oauthlib.OAuth2Session(scope=scope, client_id="sample-client-id")
            url, state = oauth.authorization_url(auth_url)
        logging.debug("state: {}  url: {}".format(state,url))
        return oauth, state

    def send(self, args, session=None):
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

                elif sec.type_ == "oauth2":
                    # If current session object isn't an oauth2 object we replace it with one
                    if not isinstance(session, requests_oauthlib.oauth2_session.OAuth2Session):
                        session, state = self.connect_oauth(sec)
                        if session is None:
                            logging.error("Oauth connection failed")
                            sys.exit(0)
                    # Check if current session scope contains all scopes of the current sec
                    # If not create new session
                    scopes = sec.get_scopes()
                    scopes = scopes["implicit"]
                    logging.debug("Scopes: {}".format(scopes))
                    if not all(elem in session.scope for elem in scopes):
                        logging.debug("Scopes don't match {} {}".format(session.scope, scopes))
                        session, state = self.connect_oauth(sec)


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
            self.header["Content-Type"] = self.content[0].type_#"application/json"
            request_body = self.content[0]
        elif self.content is not None:
            for r in self.content:
                if r.type_ == "application/json":
                    request_body = r
                    # This should be technically right.
                    # Alternative ways: Check header and x-* fields for headers
                    # Try without and after 415 (unsupported media type) do this
                    self.header["Content-Type"] = r.type_
                    break
        if request_body is not None:
            request_body = request_body.json()

        # TODO rethink requests creation.
        # Tämä on vähän purkka. Multipart viestittely ei toimi requests jos itse asettaa header
        # Olisi hyvä harkita sitä, ettei itse aseta koko header jos tämän saisi niin toimimaan
        try:
            if self.header["Content-Type"] == "multipart/form-data":
                del self.header["Content-Type"]
        except KeyError:
            logging.debug("")
        # Endpoints should be named in a format like /<name>/ but servers can be either
        # <url>/ or <url>. In case the url ends with / it should be removed
        if self.url.base[0].endswith('/'):
            self.url.base[0] = self.url.base[0][:-1]
        r_url = ''.join((self.url.base[0], self.url.endpoint))

        d = {}
        if args.cheader:
            d[args.cheader[0]] = args.cheader[1]
            # self.header = {**self.header, **d}

        # If there is no Session then we create a new one
        if session is None:
           session = requests.Session()

        try:
            # Replace {par} with urlparameter
            if self.url.parameter is not None:
                r_url = re.sub('{.*}', str(self.url.parameter), r_url, flags=re.DOTALL)

            logging.debug("\nSending {} to {} ".format(self.method, r_url))
            logging.debug("Header params: {}\n Cookie params: {}\n Query params: {}\n Path params: {}\n Content: {}\n Files: {}".format(
                {**self.par_header, **self.sec_header, **self.header, **d}, {**self.par_cookie, **self.sec_cookie}, {**self.par_query, **self.sec_query}, self.url.parameter, request_body, self.files))
            if self.method == "GET":
                r = session.get(r_url,
                                 headers={**self.par_header, **self.sec_header, **self.header, **d}, cookies={**self.par_cookie, **self.sec_cookie},
                                 params={**self.par_query, **self.sec_query}, data=request_body, files=self.files,
                                 allow_redirects=self.ALLOW_REDIRECTS)

            elif self.method == "POST":
                r = session.post(r_url,
                                 headers={**self.par_header, **self.sec_header, **self.header,**d}, cookies={**self.par_cookie, **self.sec_cookie},
                                 params={**self.par_query, **self.sec_query}, data=request_body, files=self.files,
                                  allow_redirects=self.ALLOW_REDIRECTS)

            elif self.method == "DELETE":
                r = session.delete(r_url,
                                 headers={**self.par_header, **self.sec_header, **self.header, **d}, cookies={**self.par_cookie, **self.sec_cookie},
                                 params={**self.par_query, **self.sec_query}, data=request_body, files=self.files,
                                    allow_redirects=self.ALLOW_REDIRECTS)

            elif self.method == "PUT":
                r = session.put(r_url,
                                 headers={**self.par_header, **self.sec_header, **self.header, **d}, cookies={**self.par_cookie, **self.sec_cookie},
                                 params={**self.par_query, **self.sec_query}, data=request_body, files=self.files,
                                 allow_redirects=self.ALLOW_REDIRECTS)

            else:
                logging.error("Error sending request. Method not found")
                return False, False, False

            return r.status_code, r, session
        except ValueError:
            # Requests library checks that header values can't contain \n and such RFC 7230 protocol stuff
            # This means it crashes when radamsa gives it some fancy values.
            # This is good because now incoming requests should be in proper form
            logging.exception("ValueError in req.send")
        except Exception:
            logging.exception(
                "Header params: {}\n Cookie params: {}\n Query params: {}\n Path params: {}\n Content: {}\n Files: {}".format(
                    {**self.par_header, **self.sec_header, **self.header, **d}, {**self.par_cookie, **self.sec_cookie},
                    {**self.par_query, **self.sec_query}, self.url.parameter, request_body, self.files))
        # Should we still return session if send crashes?
        return None, None, session

    def use_good_values(self, good_values):
        '''
        Changes parameter values to same ones that can be found from good_values
        This method might be too "dumb" and need work later
        :param good_values:
        :return:
        '''
        logging.debug("Using use_good_values")
        logging.debug("Self.parameters: {}\n".format(len(self.parameters)))
        for par in self.parameters:
            logging.debug(par.name)
        logging.debug("Good values: {}".format(len(good_values)))
        for par in good_values:
            logging.debug(par.name)
           # logging.debug(par.value)

        #Parameters.
        for p in self.parameters:
            for good in good_values:
                if p.name == good.name:
                    logging.debug("Replaced {} {} with {} {}".format(p.name, p.value, good.name, good.value))
                    p.value = good.value
                elif p.format_ != "object" and good.format_ == "object":
                    self.good_object(p, good)

        # Requestbody
        for rbody in self.content:
            if rbody.params is not None:
                for p in rbody.params:
                    for good in good_values:
                        logging.debug("Replaced {} {} with {} {}".format(p.name, p.value, good.name, good.value))
                        if p.name == good.name:
                            p.value = good.value
                        elif p.format_ != "object" and good.format_ == "object":
                            self.good_object(p, good)
        return

    def good_object(self, p, g):
        '''
        Helper function for use_good_values.
        :param p:
        :param g:
        :return:
        '''
        for par in g.value:
            if par.name == p.name:
                logging.debug("Replaced {} {} with {} {}".format(p.name, p.value, par.name, par.value))
                p.value = par.value
            elif par.format_ != "object" and p.format_ == "object":
                self.good_object(par, g)

    def return_from_nested(self, parameter, name_list):
        '''
        Helper function for return_pars. Appends parameters to name_list
        :param parameter:
        :param name_list:
        :return:
        '''
        logging.debug("Req/return_pars/nested: {} added".format(parameter.name))
        name_list.append(parameter)
        try:
            if parameter.format_ in self.arrays or parameter.format_ in self.objects:
                # If parameter is array or obj it has other parameters within
                # Except obj can contain a single array or obj value
                #print(parameter, parameter)
                for par in parameter.value:
                    if par.format_ in self.objects or par.format_ in self.arrays:
                        name_list = self.return_from_nested(par, name_list)
                    else:
                        logging.debug("Req/return_pars/nested: {} added".format(par.name))
                        name_list.append(par)

        except TypeError:
            # Invoked when obj contains a single array
            logging.exception("Return_from_nested TypeError")
            if parameter.format_ in self.objects or parameter.format_ in self.arrays:

                name_list = self.return_from_nested(parameter.value, name_list)

        except AttributeError:
            # Invoked in cases when obj or array contain a single string.
            # In case of petshop triggering this might be a bug
            logging.exception("Return_from_nested AttributeError")
            return name_list

        return name_list

    def return_pars(self):
        '''
        Returns parameter names of all parameters within self.parameters and self.content
        Iterates through both and appends their names.
        If parameter is either object or array uses return_from_nested to get the inner variables
        '''
        logging.debug("Req {}{}".format(self.url.base, self.url.endpoint))
        ret = []
        for par in self.parameters:

            if par.format_ in self.objects or par.format_ in self.arrays:
                ret = self.return_from_nested(par, ret)
            else:
                logging.debug("Req/return_pars: {} added".format(par.name))
                ret.append(par)

        for rbody in self.content:
            for par in rbody.params:
                if par.format_ in self.objects or par.format_ in self.arrays:
                    ret = self.return_from_nested(par, ret)
                else:
                    logging.debug("Req/return_pars: {} added".format(par.name))
                    ret.append(par)
        return ret

    def valid_response_codes(self):
        '''
        Returns a list containing all the valid response codes for this request.
        Return codes are integers due to requests library returning integer codes.
        Non int values like default are appended as they are.
        :return:
        '''
        rcodes = []
        for resp in self.responses:
            try:
                rcodes.append(int(resp.code))
            except ValueError:
                rcodes.append(resp.code)
        logging.debug("{}{} {}".format(self.url.base, self.url.endpoint, self.method))
        logging.debug("valid_response_codes {}".format(rcodes))
        return rcodes
