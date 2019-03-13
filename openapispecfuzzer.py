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
import parsers
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
        print(subprocess.check_output(['mkdir', '-p', folder]))


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


# Takes $ref link and returns content
def ref_content(ref_string, api_json):
    # reference can be in either spec document (link starts with #) or within other document
    ref_split = ref_string.split("/")
    ref = None
    ref_name = ref_split[len(ref_split)-1]
    if ref_split.pop(0) == "#":
        # ref is in api object
        for level in ref_split:
            api_json = api_json.get(level)
        ref = api_json
    else:
        logging.error("Application currently only supports fetching references from the api spec file.")

    return ref, ref_name


def request_generator(api, args):
    # Logging block
    logging.info("API name: {}".format(api.info.apiName))
    logging.info("API version: {}".format(api.info.apiVersion))
    logging.info("OpenAPI documents version: {}".format(api.info.openApiVersion))
    logging.info("Description: {}".format(api.info.apiDescription))
    logging.info("API endpoints and their methods")
    for p in api.paths:
        logging.info(p.path)
        '''
        if p.get is not None:
            logging.info("  GET")
        if p.post is not None:
            logging.info("  POST")
        if p.delete is not None:
            logging.info("  DELETE")
        if p.put is not None:
            logging.info("  PUT")
        '''
        for method, content in p.endpoint().items():
            logging.info("      {}".format(method))
            for param in content.parameters:
                logging.info("          {} {} {}".format(param.name, param.format_, param.location))
    logging.debug("Total number of endpoints is {}".format(api.amount()))
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
            result = create_request(path, args, good_values)
            # If creation was successful add to legit_requests
            if result is not False:

                legit_requests.append(result)
                # Save all values that went through.
                for p in result.parameters:

                    good_values.append(p.value)

        #legit_requests.append(create_request(path))
    logging.info("Generated {} legit requests".format(len(legit_requests)))
    logging.error("END OF CODE. Lazy bastard code more")


def create_request(path, args, good_values=None):
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
            content = m.requestBody

            security = m.security
            req = req_model.Req(url, parameters, method, header, content, security)
            req.set_dummy_values()
            looping = True
            for i in range(ATTEMPTS):
                logging.debug("Sending to {}.".format(path.path))
                code, r = req.send(args)
                logging.debug("Received code {}".format(code))
                if code == 200:
                    m.has_request = True
                    logging.debug("Good request created {}{}{} {}".format(req.url.base,
                                                                          req.url.endpoint, req.url.parameter,
                                                                          req.method))

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
                content, name = ref_content(value.get("$ref"), full_dict)
                # idea is to replace the parent node of $ref with a dict schemaname: content
                dict2 = dict()
                dict2[name] = content
                newdict[key] = dict2
                ref_content(value.get("$ref"), full_dict)
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
    parser.add_argument('-apikey', dest='apikey',
                        help='Api key. Used if the target api has an api key security scheme')
    parser.add_argument('-server', dest='server',
                        help='Parameter given to this argument will replace specs server variable')
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
    "fuzz_variable_identifier": "$",
    # folder containing specs
    "target_folder": "targets"
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
    with open('modified.json', 'w') as outfile:
        json.dump(api, outfile)
    if str(api.get("openapi")).startswith("3."):
        api = parsers.openapi3(api,args)
    elif str(api.get("openapi")).startswith("2."):
        parsers.openapi2(api)
    else:
        logging.error("Openapi version isn't 2 or 3. Version: "+api.get("openapi"))

    request_generator(api, args)


if __name__ == "__main__":
    main()
