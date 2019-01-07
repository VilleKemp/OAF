class API:
    '''
Api
    openapiVersion: string #Openapi version of the target
    
    info: Object #Contains information of the target. See below for more details
    
    paths: Array #Array containing multiple path objects.
    
    schemas: #TODO
    
    security: Object #Contains security information
    
    servers: TBD , contains the server where the api is hosted

    '''
    def __init__(self,openapiVersion,info,paths,schemas,security):
        self.openapiVersion=openapiVersion
        self.info=info
        self.paths=[]
        self.schemas=schemas
        self.security=security
        self.servers
        
        
class path:
    '''
path

    path: string # Path, for example /pets
    get,put,post,delete, options, head, patch: object #Information of the <method> object of this path
    servers: Object? #Alternative server for this path
    parameters: object #Parameters for this path
    '''
    def __init__(self, path,get,put,post,delete,options,head,patch,servers,parameters):
        self.path=path
        self.get=get
        self.put=put
        self.post=post
        self.delete=delete
        self.options=options
        self.head=head
        self.patch=patch
        self.servers=servers
        self.parameters=parameters

class operation:

    '''
    operationId: string #unique id for the operation
    parameters: object #parameters for this operation
    requestBody: object #requestbody
    responses: object #responses to this operation
    callback: #TODO needed?
    security: object
    servers: servers
    '''

    def __init__(self,operationId,parameters,requestBody,responses,callback,security,servers):
        self.operationId=operationId
        self.parameters=parameters
        self.requestBody=requestBody
        self.responses=responses
        self.callback=callback
        self.security=security
        self.servers=servers

class parameters:

class requestBody:
    '''
    content: string #request format
    required: boolean #Is this required or not
    '''

    def __init__(self, content,required):
        self.content=content
        self.required=required

class responses:

class info:

class schemas:

class security:

class servers:
