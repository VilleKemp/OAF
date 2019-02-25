import argparse
import json
import yaml
import subprocess
import logging
import os.path
import sys
import requests
import model3 as model
import req as req_model

##GLOBALS##
ATTEMPTS = 20

##


def initialize_logger(output_dir):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
     
    # create console handler and set level to info
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
 
    # create error file handler and set level to error
    handler = logging.FileHandler(os.path.join(output_dir, "error.log"),"w", encoding=None, delay="true")
    handler.setLevel(logging.ERROR)
    formatter = logging.Formatter("%(asctime)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
 
    # create debug file handler and set level to debug
    handler = logging.FileHandler(os.path.join(output_dir, "log.log"),"w")
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def ramdasa(amount, testcase_folder, seed_folder):
    
    case_name = 'fuzzcase'
    output = testcase_folder+'/'+case_name+'-%n'
    
    # Go to testcase_folder, check if files exist, generate files if needed from files in folder seed
    query = ['ls', testcase_folder, '|', 'grep', '-q', case_name, '|', '|', 'radamsa', '-n', output, seed_folder + '/*']
    print(subprocess.check_output(query))
    
    # Take one of the fuzzcases, use it and then remove it from the pool of files that the above script checks
    # TODO Exact way this is used is not yet decided
    file_under_use='placeholder.txt'
    print(subprocess.check_output(['mv','"$(ls',testcase_folder, '|', 'head','-n 1)"', file_under_use]))


def create_folders(folders):
    # Create all the folders that the program needs for working
    for folder in folders:
        print(subprocess.check_output(['mkdir','-p',folder]))


def readfile(api):
    # Read yaml or json file
    logging.info('Reading api file')
    with open(api) as f:
        if api.endswith(".json"):
            data = json.load(f)
        elif api.endswith(".yaml"):
            data = yaml.safe_load(f)
        else:
            logging.error('Error reading api specification')
    return data


def handle_ref(ref, schemas):
    # Helper function that takes a ref link and outputs a schema
    # Split the url with / and check if the last word is already in schemas. If so return the schema
    split = ref.split("/")
    if split[len(split)-1] in schemas:
        return schemas.get(split[len(split)-1]), schemas
    else:
    # TODO If the schema wasn't in the openapi files schema object, fetch it and add to schema object
        return "", schemas


# Parses openap3 spec and returns api object defined in model
def openapi3(json):
    # Parsing of openapi 3.x.x
    logging.info("Api version "+json.get("openapi"))

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
        for method in paths[endpoint]:

            if "operationId" in paths[endpoint][method]:
                operation_id = paths[endpoint][method]["operationId"]

            if "requestBody" in paths[endpoint][method]:
                request_body = paths[endpoint][method]["requestBody"]

            new_method = model.Method(operation_id, request_body)

            # Check if method specific server exists. If not add servers object from the root
            # TODO remove parameters from url
            if "servers" in paths[endpoint][method]:
                new_method.add_server(paths[endpoint][method]["servers"]["url"])
            else:
                for s in json.get("servers"):
                    new_method.add_server(s["url"])


            # Check if method specific security exists. If not add default
            # TODO parse security information to security object
            if "security" in paths[endpoint][method]:
                new_method.add_security(paths[endpoint][method]["security"])
            else:
                new_method.add_security(json.get("security"))

            # Parse parameters
            if "parameters" in paths[endpoint][method]:
                for parameter in paths[endpoint][method]["parameters"]:
                    par_name = parameter["name"]
                    par_location = parameter["in"]
                    par_required = parameter["required"]
                    # TODO parse through schema and style and fetch relevant component?
                    if "schema" in parameter:
                        # TODO Currently does not take the format field from schema.
                        if parameter["schema"].get("type"):
                            par_format = parameter["schema"].get("type")
                        else:
                            par_format = parameter["schema"]
                    elif "style" in parameter:
                        par_format = parameter["style"]
                    else:
                        logging.error("No parameter schema or style detected")
                        par_format = None
                    new_parameter = model.Parameter(par_name, par_location, par_required, par_format)
                    new_method.add_parameter(new_parameter)

            # Responses.
            for response in paths[endpoint][method]["responses"]:
                # print(paths[endpoint][method]["responses"][response])
                try:
                    content = paths[endpoint][method]["responses"][response]["content"]
                except KeyError:
                    content = None
                new_response = model.Response(response, content)
                new_method.add_response(new_response)
            if not new_path.new_method(new_method, method):
                logging.error("Adding method to path failed")

        api.add_path(new_path)
    logging.info("Spec parsed and api object created")
    return api


# Takes $ref link and returns content
def ref_content(ref_string, api_json):
    # reference can be in either spec document (link starts with #) or within other document
    ref_split = ref_string.split("/")
    ref = None
    if ref_split.pop(0) == "#":
        # ref is in api object
        for level in ref_split:
            api_json = api_json.get(level)
        ref = api_json
    else:
        logging.error("Application currently only supports fetching references from the api spec file.")

    return ref


def openapi2(api):
    # TODO Implement a parser for openapi 2.x.x
    logging.info("Api version " + api.get("openapi"))
    logging.error("Version not yet supported")


def request_generator(api):
    # Logging block
    logging.info("API name: {}".format(api.info.apiName))
    logging.info("API version: {}".format(api.info.apiVersion))
    logging.info("OpenAPI documents version: {}".format(api.info.openApiVersion))
    logging.info("Description: {}".format(api.info.apiDescription))
    logging.info("API endpoints and their methods")
    for p in api.paths:
        logging.info(p.path)
        if p.get is not None:
            logging.info("  GET")
        if p.post is not None:
            logging.info("  POST")
        if p.delete is not None:
            logging.info("  DELETE")
        if p.put is not None:
            logging.info("  PUT")
    legit_requests = []
    # Should this be good_values = {"int": [], "str": [] } ?
    good_values = []




    '''
    amount of requests = amount of methods in paths
    
    
    '''
    # TODO tässä on aivopieru
    while len(legit_requests) != api.amount():
        # Go over each path
        for path in api.paths:
        # Give path to create_request
            result = create_request(path, good_values)
            # If creation vas succesfull add to legit_requests
            if result is not False:
                legit_requests.append(result)
                # Save all values that went through.
                for p in result.parameters:

                    good_values.append(p.value)




        #legit_requests.append(create_request(path))
    logging.info("Generated {} legit requests".format(len(legit_requests)))
    logging.error("END OF CODE. Lazy bastard code more")


def create_request(path, good_values=None):
    '''
    # Creates a functional request
    Constructs a req object
    sets a dummy value to parameters if they exists
    sends the requests
    if response code is 2xx returns the request. Otherwise loops
    '''

    method = path.get_methods()
    method_obj = path.endpoint()
    for method, m in method_obj.items():
        if m.has_request is not True:
            url = req_model.Url(m.server, path.path)
            parameters = m.parameters
        # TODO find out the headers
            header = None
        # TODO content
            content = None
            req = req_model.Req(url, parameters, method, header, content)
            req.set_dummy_values()
            looping = True
            for i in range(ATTEMPTS):
                logging.debug("Sending to {}.".format(path.path))
                code, r = req.send()
                logging.debug("Received code {}".format(code))
                if code is "200":
                    m.has_request = True
                    return req
                else:

                    req.set_dummy_values()

        return False


def ref_parser(datadict, full_dict):
    # parses over the dict and replaces parent of a $ref with result of ref_content

    # deepcopy before data manipulation
    from copy import deepcopy
    newdict = deepcopy(datadict)

    for key, value in datadict.items():
        # recurse into nested dicts
        if isinstance(value, dict):
            if value.get("$ref"):
                newdict[key] = ref_content(value.get("$ref"), full_dict)
            else:
                newdict[key] = ref_parser(datadict[key], full_dict)
        #
        '''
        elif key == "$ref":
            newdict[key] = ref_content(value, full_dict)
        '''
    return newdict


def main():
    # Argparser
    parser = argparse.ArgumentParser(description='Fuzzer')
    parser.add_argument('-api', dest='api', help='OpenApi file', required=True)
    args = parser.parse_args()

    # Config
    ###############
    # Put these to a file later?
    config = {
    # Folder name of the folder containing fuzz corpus
    "seed_folder" : "seed",
    # Folder containing fuzzcases
    "testcase_folder":"fuzz_cases",
    # Folder containing logs
    "logs_folder": "logs",
    # How many times do we run radamsa
    "radamsa_output_amount": 1000,
    # Idea at this point is to mark parts of the requests that are going to be fuzzed with some type of identifiers. With this variable user can set it themselves.
    "fuzz_variable_identifier": "$" 
    }
    
    ################
    # If configs dictionary has a variable containing string _folder then create a folder with that name
    create_folders([value for key, value in config.items() if '_folder' in key.lower()])
    
    initialize_logger(config.get("logs_folder"))
    logging.info('Configurations: ')
    
    for key, val in config.items():
        logging.info(key+":"+str(val))

    api = readfile(args.api)
    # Parser doesn't work right if refs have nested refs. Calling multiple times fixes this.
    # TODO fix
    api = ref_parser(api, api)
    api = ref_parser(api, api)
    print(api)
    if str(api.get("openapi")).startswith("3."):
        api = openapi3(api)
    elif str(api.get("openapi")).startswith("2."):
        openapi2(api)
        
    else:
        logging.error("Openapi version isn't 2 or 3. Version: "+api.get("openapi"))

    request_generator(api)


if __name__ == "__main__":
    main()
