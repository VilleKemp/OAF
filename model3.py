class API:
    '''
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

    '''

    paths = []

    def __init__(self, info):
        self.info = info

    def add_path(self, path):
        self.paths.append(path)


class Security:
    def __init__(self, type, name, location, scheme, flows, openidconnecturl):
        self.type = type
        self.name = name
        self.location = location
        self.scheme = scheme
        self.flows = flows
        self.openidconnecturl = openidconnecturl


class Parameter:
    def __init__(self, name, location, required):
        self.name = name
        self.location = location
        self.required = required


class Response:
    def __init__(self, code, content):
        self.code=code
        self.content=content


class Info:
    def __init__(self, openapi_version, api_name, api_description, api_version):
        self.openApiVersion=openapi_version
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


class Method:
    parameters = []
    responses = []
    security = []
    server = []

    def __init__(self, operationid, requestbody):
        self.operationID = operationid
        self.requestBody = requestbody

    def add_parameter(self, parameter):
        self.parameters.append(parameter)

    def add_server(self, parameter):
        self.server.append(parameter)

    def add_response(self, parameter):
        self.responses.append(parameter)

    def add_security(self, parameter):
        self.security.append(parameter)


