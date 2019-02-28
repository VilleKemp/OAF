import logging


class API:
    """
    Info: Object, contains API information
        openApiVersion
        apiName
        apiDescription
        apiVersion

    paths List of path objects
        Path
            path: "/endpoint/"
            GET: method object
                operationID:
                parameters
                    parameter: parameter object
                        name: parameter name
                        location: query,header,path,cookie
                        required: true/false
                requestBody
                responses: list of response objects
                    code: HTTP code
                    content
                security: array of security objects
                    type: apikey,http,oauth2,openIdConnect
                    name: name of the parameter (for example cookie)
                    location: query,header,cookie
                    scheme:
                    flows:
                    openIdConnectUrl:
                servers: list of urls
                    url "www.url.url"
            POST:
                ...
            PUT:
                ...
            DELETE:
                ...

    """

    paths = []

    def __init__(self, info):
        self.info = info

    def add_path(self, path):
        self.paths.append(path)

    def amount(self):
        amount = 0
        for path in self.paths:
            amount += len(path.get_methods())
        return amount


class Security:
    def __init__(self, type_, name, location, scheme, flows, openidconnecturl, apikey=None):
        self.type_ = type_
        self.name = name
        self.location = location
        self.scheme = scheme
        self.flows = flows
        self.openidconnecturl = openidconnecturl
        self.apikey = apikey

    def get_details(self):
        return self.type_, self.name, self.location


class Parameter:
    def __init__(self, name, location, required, format_=None, value=None, options=None):
        self.name = name
        self.location = location
        self.required = required
        self.format_ = format_
        self.value = value
        # If parameter has only specific values it is allowed ot be they are stored here
        self.options = options
        logging.debug("     Parameter {} created".format(self.name))


class Response:
    def __init__(self, code, content):
        self.code = code
        self.content = content


class Info:
    def __init__(self, openapi_version, api_name, api_description, api_version):
        self.openApiVersion = openapi_version
        self.apiName = api_name
        self.apiDescription = api_description
        self.apiVersion = api_version


class Path:
    def __init__(self, path, get=None, post=None, put=None, delete=None):
        self.path = path
        self.get = get
        self.put = put
        self.delete = delete
        self.post = post

    def create_get(self, param):
        self.get = param

    def create_post(self, param):
        self.post = param

    def create_delete(self, param):
        self.delete = param

    def create_put(self, param):
        self.put = param

    def new_method(self, obj, name):
        if name == "get":
            self.get = obj
        elif name == "post":
            self.post = obj
        elif name == "put":
            self.put = obj
        elif name == "delete":
            self.delete = obj
        else:
            return False

        return True

    def endpoint(self):
        epoints = {}
        if self.get is not None:
            epoints["GET"] = self.get
        if self.put is not None:
            epoints["PUT"] = self.put
        if self.delete is not None:
            epoints["DELETE"] = self.delete
        if self.post is not None:
            epoints["POST"] = self.post
        return epoints

    def get_methods(self):
        methods = []
        if self.get is not None:
            methods.append("GET")
        if self.put is not None:
            methods.append("PUT")
        if self.delete is not None:
            methods.append("DELETE")
        if self.post is not None:
            methods.append("POST")
        return methods


class Method:

    def __init__(self, operationid, requestbody):
        self.operationID = operationid
        self.requestBody = requestbody
        self.has_request = False
        self.parameters = []
        self.responses = []
        self.security = []
        self.server = []

    def add_parameter(self, parameter):
        self.parameters.append(parameter)

    def add_server(self, parameter):
        self.server.append(parameter)

    def add_response(self, parameter):
        self.responses.append(parameter)

    def add_security(self, parameter):
        self.security.append(parameter)

    def set_has_request(self, param):
        self.has_request = param

    def get_security(self):
        return self.security


