class API:
#Modeled after openapi 3 spec. Idea is that this is the object that is given to the case generator. This way you can create parsers that generate this class from openapi2, blueprint or similar specs

#Version(string): Openapi version. Located in the "openapi" paremeter of the openapi3 spec
#info(object): info field of the openapi3 spec
#paths(array[object]): array containing path objects.
#schemas(array[object]): array containing schema objects
#security(?): security information #TODO create a security object
#tag(?): tags field of the openapi3 spec.#TODO
    def __init__(self,version,info,paths,schemas,components,security,tags):
        self.version=version
        self.info=info
        self.paths=[]
        self.schemas=[]
        self.components=components
        self.security=security
        self.tags=tags
        
    #method to add individual paths to the paths array    
    def add_path(path):
        self.paths.append(path)
    #method to add individual schemas to the schemas array      
    def add_schema(schema):
        self.schemas.append(schema)

class info:
#Contains info fields information
#Version(string): Api version. Do not confuse with openapi version
#title(string): Apis name
    def __init__(self,version,title):
        self.version=version
        self.title=title
            
class path:
#path(string): 
#summary(string)
#description(string)
#operations(array[object])
#server(string)#TODO check if this needs to be an array
#parameters #TODO
    def __init__(self,path,summary,description,operations,server,parameters):
        self.path=path
        self.summary=summary
        self.description=description
        self.operations=[]
        self.server=server
        self.parameters=[]

class operation:
    def __init__(method,tags,summary,description,operationId,parameter,requestBody,responses,callbacks,deprecated,security,servers):
        self.method=method
        self.tags=tags
        self.summary=summary
        self.description=description
        self.operationId=operationId
        self.parameter=parameter
        self.requestBody=requestBody
        self.responses=responses
        self.callbacks=callbacks
        self.deprecated=deprecated
        self.security=security
        self.servers=servers
        
class schema:
    #Likely not needed. 
    def __init__():
       #TODO
       print("")
#Single schema object
