import logging
import model3 as model
import sys
# TODO used while debugging. Remove if not needed
import time

def create_security(security):
    # Generates a security object from security dict.
    s_type = security["type"]
    s_name = None
    s_location = None
    s_scheme = None
    s_flows = None
    s_ourl = None
    s_apikey = None
    # logging.debug("Creating security object")
    # logging.debug("Object is {}".format(security))
    # logging.debug("Type is {}".format(s_type))
    if s_type == "apiKey":
        s_name = security.get("name")
        s_location = security.get("in")
        logging.debug("name {} location {}".format(s_name, s_location))
    elif s_type == "http":
        s_scheme = security["scheme"]
    elif s_type == "oauth2":
        s_flows = security["flows"]
    elif s_type == "openIdConnect":
        s_ourl = security["openIdConnectUrl"]

    return model.Security(s_type, s_name, s_location,
                                                   s_scheme, s_flows, s_ourl, s_apikey)


def handle_object(val, name=None):
    '''
    Handles variables that are type object.
    Goes over its "properties" field and generates Parameter object for each of them.
    Returns a Parameter object with value field containing other Parameters


    :param val:
    :return: Parameter object that has a type of object and value containing its parameters
    as Parameter objects

    #TODO this and handle array must take in to consideration the following
    category case. Joskus key on {'Category': {'title': 'Pet category', 'type': 'object', 'properties': {'id': {'type': 'integer', 'format': 'int64'}, 'name': {'type': 'string'}}, 'description': 'A category for a pet', 'example': {'name': 'name', 'id': 6}, 'xml': {'name': 'Category'}}}
 => jos type ei löydy mene taso alaspäin
    SHOULD WORK.

 joskus tietoa on xml objectin alla.
 WIP
    '''
    parameters = []
    required_parameters = val.get("required")
    if required_parameters is None:
        required_parameters = []

    for key, value in val.get("properties").items():
        #print("Handle object")
        #print(key, value)
        # This is supposed to fix category case
        name_ = None
        if value.get("type") is None:
            name_ = next(iter(value))
            value = value[name_]
            #print("NEW VALUE: {}".format(value))

        if value.get("type") == "object":
            if name_ is not None:
                parameters.append(handle_object(value, name_))
            else:
                parameters.append(handle_object(value))
        elif value.get("type") == "array":
            if name_ is not None:
                parameters.append(handle_array(value, name_))
            else:
                parameters.append(handle_array(value))
        else:
            parameters.append(model.Parameter(key, "requestBody",
                                              key in required_parameters, value.get("type"),
                                              value.get("format"), None, value.get("enum")))

    obj_parameter = model.Parameter(name, "requestBody", val.get("required"), val.get("type"),
                                    val.get("format"), parameters)
    #print("###############################")
    #obj_parameter.print_info()
    #print("################################")
    return obj_parameter


def handle_array(val, name=None):
    '''
    Handles array parameters. Logic is same as in handle object
    :param val:
    :return:
    '''
    parameters = []
    required_parameters = val.get("required")

    for key, value in val.get("items").items():
        # IF the array only contains  a parameter with no name(For example {type: string}) value.get fails.
        try:
            if value.get("type") == "object":
                parameters.append(handle_object(value))
            elif value.get("type") == "array":
                parameters.append(handle_array(value))
            else:
                parameters.append(model.Parameter(key, "requestBody",
                                                  key in required_parameters, value.get("type"), value.get("format"),
                                                  None, value.get("enum")))
        except AttributeError:
            # TODO this can't be the best way to fix above mentioned issue
            logging.error("Attribute error at handle_array. ")
            if key == "type":
                valkey = value
            else:
                valkey = None
            array_parameter = model.Parameter(name, "requestBody", val.get("required"), valkey, val.get("format"), parameters)

            return array_parameter
    array_parameter = model.Parameter(name, "requestBody", val.get("required"), val.get("type"), val.get("format"), parameters)

    return array_parameter


# Create requestBody object
def create_request_body(rb):
    rbodies = []
    # If the requestBody was a reference current rb object isn't in right form. It has to be checked and fixed

    if rb.get("content") is None:
        name = next(iter(rb))
        rb = rb[name]
    logging.debug("Creating requestbody")
    #logging.debug("rb is : {}".format(rb))

    required = rb.get("required")
    # loop the content. Create new requestbody object for each parameter
    for key, value in rb.get("content").items():
        logging.debug("\nProcessing {}".format(key))
        new_rbody = model.RequestBody(key, required)
        # if schema was a $ref there is one more layer before we get to types etc
        schema = value.get("schema")
        s_name = None
        if schema.get("type") is None:
            s_name = next(iter(schema))
            schema = schema[s_name]

        # ###### REQUESTBODY SCHEMA PARSING ###################
        #logging.debug("\nSchema {}".format(schema))
        if schema.get("type") == "object":
            new_parameter = handle_object(schema, s_name)
        elif schema.get("type") == "array":
            new_parameter = handle_array(schema, s_name)
        else:
            new_parameter = model.Parameter(schema.get("name"), "requestBody", schema.get("required"), schema.get("type"),
                                            schema.get("format"), None, schema.get("enum"))

        new_rbody.add_parameter(new_parameter)

        new_rbody.print_info()

        rbodies.append(new_rbody)

    return rbodies


# Parses openap3 spec and returns api object defined in model
def openapi3(json, args):

    # Creating logger
    logging.getLogger("Parser")

    # Parsing of openapi 3.x.x
    logging.info("Api version " + json.get("openapi"))

    # Parsing objects out from api file

    logging.info("Parsing")
    # These are REQUIRED
    paths = json.get("paths")
    info_obj = json.get("info")
    openapi = json.get("openapi")

    # Validating that required fields exist
    if paths is None or info_obj is None or openapi is None:
        logging.error("Api spec is missing either paths, info or openapi field. These fields are mandatory")
        sys.exit()

    # Creating info object
    apititle = info_obj.get("title")
    apidesc = info_obj.get("description")
    apiversion = info_obj.get("version")
    logging.info("Generating objects")
    info = model.Info(openapi, apititle, apidesc, apiversion)

    # Creating API object
    api = model.API(info)

    operation_id = None
    request_body = None

    # Parsing
    for endpoint in paths:
        new_path = model.Path(endpoint)
        logging.debug("Parsing path {}".format(endpoint))
        for method in paths[endpoint]:
            # TODO Parse all the x- fields from method
            logging.debug("     Parsing method {}".format(method))
            new_method = model.Method(operation_id)
            if "operationId" in paths[endpoint][method]:
                operation_id = paths[endpoint][method]["operationId"]

            if "requestBody" in paths[endpoint][method]:
                request_body_list = create_request_body(paths[endpoint][method]["requestBody"])
                new_method.replace_request_body(request_body_list)
            # Check if method specific server exists. If not add servers object from the root
            # TODO remove parameters from url
            # If args server exists. Only add that to the server variable
            if args.server:
                new_method.add_server(args.server)
            else:
                if "servers" in paths[endpoint][method]:
                    new_method.add_server(paths[endpoint][method]["servers"]["url"])
                else:
                    for s in json.get("servers"):
                        new_method.add_server(s["url"])

            # Check if method specific security exists. If not add default
            # ########## SECURITY PARSING #################

            if "security" in paths[endpoint][method]:
                # If method contains a security object use it
                security = paths[endpoint][method]["security"]
            elif "security" not in paths[endpoint][method] and json.get("security") is not None:
                # If method specific security object doesn't exists use general if it exists
                # TODO needs testing. Current test cases never call this
                security = json.get("security")
            else:
                # If above techniques fail we assume there is no security scheme
                security = None

            # If securitySchemes exists we need to take it into accounts due to
            # Api likely using it to store security information
            if json["components"]["securitySchemes"] and security is not None:
                # print(security)
                for s in security:
                    key = list(s.keys())[0]
                    # print(key)
                    if key in json["components"]["securitySchemes"]:
                        #logging.debug(json["components"]["securitySchemes"][key])
                        new_method.add_security(create_security(json["components"]["securitySchemes"][key]))
            else:
                if security is not None:
                    new_method.add_security(create_security(security))

            # ################
            # #####PARAMETER PARSING ##################
            # TODO Seems to return incorrect parameter locations
            logging.debug("     Parsing parameters")
            if "parameters" in paths[endpoint][method]:
                for parameter in paths[endpoint][method]["parameters"]:
                    #logging.debug("Parameter found {}".format(parameter))
                    par_name = parameter["name"]
                    par_location = parameter["in"]
                    try:
                        par_required = parameter["required"]
                    except KeyError:
                        par_required = None
                    par_value = None
                    if "schema" in parameter:
                        logging.info("Schema in parameter {}".format(parameter))
                        if parameter["schema"].get("type"):
                            par_format = parameter["schema"].get("type")
                            par_format_detailed = parameter["schema"].get("format")
                            logging.info("Parameter format: {}".format(par_format))
                            # TODO remove commented code after parser works
                            # This part assumes that there is only one parameter within the array.
                            # It creates a new parameter object within the array parameter.
                            if par_format == "array":
                                # Set values to None
                                par_name_ = None
                                par_options_ = None
                                par_location_ = None
                                par_required_ = None
                                par_format_ = None
                                par_value_ = None

                                par_format_detailed_ = None
                                # Parse all of the fields looking for variables above
                                for item, value in parameter["schema"]["items"].items():
                                    if item == "name":
                                        par_name_ = value
                                    elif item == "enum":
                                        par_options_ = value
                                    elif item == "required":
                                        par_required_ = value
                                    elif item == "type":
                                        par_format_ = value
                                    elif item == "default":
                                        par_value_ = value
                                    elif item == "format":
                                        par_format_detailed_ = value
                                par_value = model.Parameter(par_name_, par_location_, par_required_,
                                                            par_format_, par_format_detailed_, par_value_, par_options_)

                                '''
                                This is old code that did not work. Saved because I might have to use it later
                                
                                par_value = []
                                for item in parameter["schema"]["items"]:
                                    logging.info("Parsing array parameter {}".format(item))
                                    par_name_ = None
                                    par_options_ = None
                                    par_location_ = None
                                    par_required = None

                                    if item["name"]:
                                        logging.info("GREP1")
                                        par_name_ = item["name"]

                                    if "enum" in item:
                                        logging.info("GREP")
                                        par_options_ = item["enum"]

                                    if item["required"]:
                                        par_required_ = item["required"]

                                    par_format_ = item["type"]

                                    par_value.append(model.Parameter(par_name_, par_location_,
                                                                     par_required_, par_format_, par_options_))
                                # Add array parameter containing other parameters to method
                                new_method.add_parameter(model.Parameter(par_name, par_location,
                                                                         par_required, par_format, par_value))
                                '''
                        else:
                            par_format = parameter["schema"]

                    elif "style" in parameter:
                        par_format = parameter["style"]
                    else:
                        logging.error("No parameter schema or style detected")
                        par_format = None

                    new_parameter = model.Parameter(par_name, par_location, par_required,
                                                    par_format, par_format_detailed, par_value)

                    allowed = True
                    for par in new_method.parameters:
                        if par.name == new_parameter.name:
                            allowed = False
                    if allowed is True:
                        new_method.add_parameter(new_parameter)
            logging.debug("Parameters {}".format(new_method.parameters))
            ####################################
            # #######RESPONSE PARSING . ####################
            for response in paths[endpoint][method]["responses"]:
                # print(paths[endpoint][method]["responses"][response])
                try:
                    content = paths[endpoint][method]["responses"][response]["content"]
                except KeyError:
                    content = None
                logging.debug("Adding response {} {}".format(endpoint, method))
                logging.info(response)
                logging.info(content)
                new_response = model.Response(response, content)
                new_method.add_response(new_response)
            if not new_path.new_method(new_method, method):
                logging.error("Adding method to path failed")
            #########################################
        api.add_path(new_path)
    logging.info("Spec parsed and api object created")
    return api


def openapi2(api):
    # TODO Implement a parser for openapi 2.x.x
    logging.info("Api version " + api.get("openapi"))
    logging.error("Version not yet supported")
