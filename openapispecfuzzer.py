import argparse
import json
import yaml
import subprocess
import logging
import os.path
import sys
import model3 as model


def initialize_logger(output_dir):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
     
    # create console handler and set level to info
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
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
    
            
def openapi3(json):
    # Parsing of openapi 3.x.x
    logging.info("Api version "+json.get("openapi"))

    # Parsing objects out from api file
    
    logging.info("Parsing")
    # These are REQUIRED
    paths = json.get("paths")
    info_obj = json.get("info")
    openapi = json.get("openapi")

    # Validating that required fields exisist
    if(paths== None or info_obj== None or openapi== None):
        logging.error("Api spec is missing either paths, info or openapi field. These fields are mandatory")
        sys.exit()

    # Creating info object
    apititle = info_obj.get("title")
    apidesc = info_obj.get("description")
    apiversion = info_obj.get("version")
    logging.info("Generating objects")
    info = model.info(openapi, apititle, apidesc, apiversion)

    # Creating API object
    api = model.API(info)


def openapi2(api):
    # TODO Implement a parser for openapi 2.x.x
    logging.info("Api version "+api.get("openapi"))
    logging.error("Version not yet supported")


def main():
    # Argparser
    parser = argparse.ArgumentParser(description='Fuzzer')
    parser.add_argument('-api',dest='api', help='OpenApi file', required=True)
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
    
    for key,val in config.items():
        logging.info(key+":"+str(val))

    api = readfile(args.api)
    
    if str(api.get("openapi")).startswith("3."):
        openapi3(api)
    elif str(api.get("openapi")).startswith("2."):
        openapi2(api)
        
    else:
        logging.error("Openapi version isn't 2 or 3. Version: "+api.get("openapi"))


if __name__ == "__main__":
    main()
