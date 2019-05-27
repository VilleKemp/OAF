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
import itertools
import random
import copy
##GLOBALS##
# Move these to config at some point
ATTEMPTS = 30
UNTIL_GIVE_UP = 5
ACCEPTED_CODES = [200, 201, 204, 303]
DUPLICATES_COUNT = 3
CHAIN_LENGTH = 3





def initialize_logger(output_dir):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
     
    # create console handler and set level to INFO
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


def radamsa(config):
    '''
    Checks if there are fuzz cases. If not generates user specified amount of them and then return one
    :param testcase_folder:
    :param seed_folder:
    :param amount:
    :return:
    '''

    testcase_folder = config["testcase_folder"]
    seed_folder = config["seed_folder"]
    amount = config["radamsa_output_amount"]
    temp_folder = config["temp_folder"]

    case_name = 'fuzzcase'
    output = testcase_folder+'/'+case_name+'-%n.txt'
    
    # Go to testcase_folder, check if files exist, generate files if needed from files in folder seed
    # TODo after demo remove shell=True! This is a security issue.
    #query = ['ls', testcase_folder, '|', 'grep', '-q', case_name, '|', '|', 'radamsa', '-o', output, '-n', str(amount), seed_folder + '/*']
    query = 'ls ' + testcase_folder + ' | ' + 'grep ' + '-q ' + case_name + ' || ' + 'radamsa ' + '-o ' + output + ' -n ' +  str(amount) +" " +  seed_folder + '/*'
    logging.info("Query is : {}".format(query))
    logging.info(subprocess.check_output(query, shell=True))
    
    # Take one of the fuzzcases, use it and then remove it from the pool of files that the above script checks

    file_under_use = temp_folder + "/inuse.txt"
    query = 'ls ' +testcase_folder + ' | ' + 'head ' + '-n ' + '1'
    logging.info("Query2 is : {}".format(query))
    logging.debug(subprocess.check_output(query, shell=True))
    filename = subprocess.check_output(query, shell=True)
    filename = filename.decode()
    filename = filename.strip("\n")
    query = 'mv ' + testcase_folder +"/"+ str(filename)+ " " + file_under_use
    logging.info("Query3: {}".format(query))
    logging.info(subprocess.check_output(query, shell=True))

    #logging.info(subprocess.check_output(['mv','"' + testcase_folder + '/$(ls ' + testcase_folder + ' | ' + 'head' + ' -n 1)"', file_under_use], shell=True))
    logging.info("Reading {}".format(file_under_use))
    with open(file_under_use, 'r', errors='ignore') as f:
        fuzz_param = f.read()
    #logging.debug("Fuzz parameter is : {}".format(fuzz_param))
    return fuzz_param


def create_folders(folders):
    # Create all the folders that the program needs for working
    for folder in folders:
        logging.info(subprocess.check_output(['mkdir', '-p', folder]))


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

    counter = 0
    # debug variable that contains all the codes that create_request encounters
    codes = []
    session = None
    while len(legit_requests) != api.amount() and counter < UNTIL_GIVE_UP:
        # Go over each path
        counter = counter + 1
        for path in api.paths:
            # Only works with ONE skip
            logging.debug("Going to {} skip is {}".format(path.path, args.skip))
            if path.path != args.skip:
            # Give path to create_request
                for method, m in path.endpoint().items():
                    result, codes, session = create_request(path, method, m, args, good_values, codes, session)
                    # If creation was successful add to legit_requests
                    if result is not False:
                        legit_requests.append(result)
                        logging.debug("Good request received. There are {} good requests out of {} total".format(len(legit_requests), api.amount()))
                        # Save all values that went through.
                        logging.debug("URL: {}{}".format(result.url.base, result.url.endpoint))
                        for par in result.return_pars():
                            logging.debug("Adding par: {} {}\n    {}".format(par.name, par.format_, par.value))
                            good_values.append(par)
                '''
                for p in result.parameters:
                    good_values.append(p)
                for i in result.content:
                    for x in i.params:
                        good_values.append(x)
                '''
            else:
                logging.info("Skipped {}".format(path.path))
    ########## Debugging block #############

    logging.info("Generated {} legit requests".format(len(legit_requests)))
    if len(legit_requests) != api.amount():
        logging.error("Generated {}/{} requests".format(len(legit_requests), api.amount()))
    logging.info("Following codes happened: {}".format(codes))
    logging.debug("There were {} legit parameters".format(len(good_values)))
    for par in good_values:
        logging.debug("{} {}".format(par.name, par.format_))
        logging.debug(par.value)
        logging.debug(par)
    logging.info("Legit requests were")
    for r in legit_requests:
        logging.debug("     {}{}".format(r.url.base, r.url.endpoint))
        logging.debug(r.method)

        logging.debug("Parameters:")
        for p in r.parameters:
            logging.debug("     {} {}".format(p.name, p.format_))
            logging.debug("     {}".format(p.value))
        logging.debug("RequestBody")
        for p in r.content:
            for para in p.params:
                logging.info("  {}".format(para.name))
                if para.format_ != "object":
                    logging.info("  {}".format(para.value))
                else:
                    for ipar in para.value:
                        logging.info("      {}".format(ipar.name))
                        logging.info("      {}".format(ipar.value))

    ##############################################

    return legit_requests


def fuzz(reqs, valid_chains, config, args):
    '''
    Fuzzing module.
    Calls other fuzzing functions. Current logic is intentionally random.
    Currently does not save objects state.
    :param reqs:
    :return:
    '''

    logging.debug("Inputting: {} {} {} {}".format(config["testcase_folder"], config["seed_folder"], config["radamsa_output_amount"], config["temp_folder"]))
    logging.debug("Fuzzing!")
    loops = 10
    session = None
    fuzz_loop_count = 0
    while True:
        fuzz_loop_count += 1
        logging.info("Fuzzing loop: {}".format(fuzz_loop_count))
        case = random.choice([1, 2])

        if case == 1:
            current_chain = random.choice(valid_chains)

            for i in range(len(current_chain)):
                # Fuzz the last request
                if i == len(current_chain):
                    logging.debug("Fuzzing last requests parameters")
                    dumb_single_request_fuzz(current_chain[i], session, config, args)

                current_chain[i].send(args, session)
        elif case == 2:
            logging.info("Fuzzing random request")
            dumb_single_request_fuzz(random.choice(reqs), session, config, args)

        else:
            dumb_single_request_fuzz(random.choice(reqs), session, config, args)
        # New session per chain
        session = None

    return


def dumb_single_request_fuzz(r, session, config, args):
    '''

    :param r:
    :param session:
    :param config:
    :param args:
    :return:
    '''
    logging.info("{}{} {}".format(r.url.base, r.url.endpoint, r.method))
    for p in r.parameters:
        # Dumb way. Just for the demo
        logging.info("p_-:{}".format(p))
        p.value = radamsa(config)
    for o in r.content:
        for pa in o.params:
            logging.info("pa:{}".format(pa))
            if pa.format_ != "object" and pa.format_ != "array":
                pa.value = radamsa(config)
            elif pa.format_ == "object":
                placeholder_obj(pa.value, config)
            elif pa.format_ == "array":
                placeholder_array(pa.value, config)

    code, request_object, session = r.send(args, session)
    valid = r.valid_response_codes()
    if code not in valid and request_object is not None:
        # TODO create a new logger just for fuzzing errors
        logging.error("########UNDOCUMENTED CODE START###########")
        logging.error("Undocumented code {} Valid codes {}\n Sent the following:".format(code, r.valid_response_codes()))
        logging.error("{} {}".format(request_object.request.url, request_object.request.method))
        logging.error(request_object.request.headers)
        logging.error(request_object.request.body)
        logging.error("Received:")
        logging.error(request_object.headers)
        logging.error(request_object.text)
        logging.error("#########UNDOCUMENTED CODE END##########")


def placeholder_obj(params, config):
    for pa in params:
        if pa.format_ != "object" and pa.format_ != "array":
            pa.value = radamsa(config)
        elif pa.format_ == "object":
            placeholder_obj(pa.value, config)
        elif pa.format_ == "array":
            placeholder_array(pa.value, config)


def placeholder_array(params, config):
    for pa in params:
        if pa.format_ != "object" and pa.format_ != "array":
            pa.value = radamsa(config)
        elif pa.format_ == "object":
            placeholder_obj(pa.value, config)
        elif pa.format_ == "array":
            placeholder_array(pa.value, config)


def create_chains(reqs, args):
    '''
    Initially a dumb brute force way. Takes all permutations of lenght CHAIN_LENGTH and attempts to legimize them.
    :param reqs:
    :return:
    '''
    logging.info("Generating all permutations of lenght {} from list {}".format(CHAIN_LENGTH, reqs))
    all = list(itertools.permutations(reqs, CHAIN_LENGTH))
    if not args.validate_chains:
        logging.info("Not validating chains")
        return None, all
    valid = []
    all2 = []
    chain_fail = False
    count = 0
    total_chains = len(all)
    logging.info("Starting chain testing. There are {} chains and {} attempts".format(len(all), UNTIL_GIVE_UP))
    try:
        while True:
            counter = 0
            for chain in all:
                # Create a new session for each chain
                counter += 1
                logging.info("Chain {}".format(counter))
                session = None
                for req in chain:
                    if count > 1:
                        # Run the loop once with the "working" values and then start randomizing them
                        req.set_dummy_values()
                    code, response, session = req.send(args, session)
                    if code not in ACCEPTED_CODES:
                        # If response code is not valid we break this try and try again later.
                        chain_fail = True

                if chain_fail is False and chain not in valid:
                    valid.append(chain)
                else:
                    all2.append(chain)
                chain_fail = False
            all = all2[:]
            count += 1
            logging.debug("COUNTING {} {}<{}".format(count, len(valid), total_chains))
            if count > UNTIL_GIVE_UP or len(valid) >= total_chains:
                break
    except KeyboardInterrupt:
        logging.exception("Interrupted")
    logging.info("Chain creation complete. There were total of {} chains and {} attempts.".format(len(all), count))
    logging.info("Amount of chains in which every response code was valid {} was {}".format(ACCEPTED_CODES, len(valid)))

    return valid, all


def create_request(path, method, m, args, good_values=None, codes=[], session=None):
    '''
    # Creates a functional request
    Constructs a req object
    sets a dummy value to parameters if they exists
    sends the requests
    if response code is 2xx returns the request. Otherwise loops
    '''



    #logging.debug("".format(method))
    if m.has_request is not True:
        url = req_model.Url(m.server, path.path)
        #parameters = m.parameters
    # TODO Remove this if not used
        header = None
        #content = m.requestBody
        logging.info("Methods requestBody is {}".format(m.requestBody))
        for r in m.requestBody:
            logging.info(r.print_info())

        #security = m.security
        requ = req_model.Req(url, m.parameters, method, header, m.requestBody, m.security, m.responses)


        # Below is a long and messy way to do the following
        '''
        We want to utilize values that has been part of an acceptable request
        In order to do that we save all the variables that were part of acceptable requests
        We remove ones that the current endpoint doesn't want
        Then we generate unique sets of these requests that do not contain any duplicates 
        This leads to a problem when there are too many duplicate variables in the same request
        The amount of sets grows to ridiciluous amounts.
        Due to this reason all duplicates above <DUPLICATE_COUNT> are removed
        '''

        # Get duplicates
        duplicates2 = []
        for r in good_values:
            duplicates2.append(r.name)
        logging.debug("Duplicates0 {}".format(duplicates2))
        duplicates = dict.fromkeys(duplicates2)
        # logging.debug("Duplicates: {}".format(duplicates))
        for d in duplicates2:
            if duplicates[d] is None:
                duplicates[d] = 1
            else:
                duplicates[d] = duplicates[d]+1
        logging.debug("Duplicates: {}".format(duplicates))




        # prune good values
        req_pars = []
        for par in requ.return_pars():
            req_pars.append(par.name)
        logging.debug("return_pars() {}".format(req_pars))
        duplicates2 = {}
        for key, val in duplicates.items():
            if key in req_pars:
                duplicates2[key] = val
        duplicates = duplicates2
        logging.debug("Pruned: {}".format(duplicates))

        #
        logging.info("Good_values size: {}".format(len(good_values)))
        pruned_good_values = []
        for key, val in duplicates.items():
            for par in good_values:
                if par.name == key:
                    pruned_good_values.append(par)
        logging.info("After pruning: {}".format(len(pruned_good_values)))

        small_good_values = []
        try:
            small_good_values.append(good_values[0])
        except IndexError:
            small_good_values = []
        logging.info("Removing values so that there are no more than {} duplicates".format(DUPLICATES_COUNT))
        counts = {}
        for par1 in pruned_good_values:
            try:
                counts[par1.name] += 1
            except KeyError:
                counts[par1.name] = 1

            if counts[par1.name] < DUPLICATES_COUNT:
                small_good_values.append(par1)


        logging.info("After removal {}".format(len(small_good_values)))
        #logging.info(counts)



        good_sets = [[]]
        #logging.debug(good_sets)
        logging.info("Generating good sets.")
        logging.info("Endpoint contains following parameters contained in good values")
        #logging.info(duplicates)
        #logging.info(good_values)
        for key, val in duplicates.items():
            for par in small_good_values:
                if par.name == key:
                    for set in good_sets:
                        has_flag = False
                        if len(set) < 1:
                            set.append(par)
                        else:
                            for set_par in set:
                                # format check should always give != None when comparing parameter objects
                                if set_par.name == key and set_par.format_ is not None:
                                    new_set = set
                                    new_set.remove(set_par)
                                    good_sets.append(new_set)
                                    has_flag = True
                        if has_flag is False:
                            set.append(par)



        logging.info("Generated {} sets".format(len(good_sets)))

        # Randomize values
        requ.set_dummy_values()

        '''
        Loop tries to send a request <ATTEMPTS> times. 
        First try is always done with random values.
        Following tries use previously generated good_sets until they are exhausted.
        After that random values are used.  
        '''
        for i in range(ATTEMPTS):

            logging.debug("Sending to {}".format(path.path))
            code, r, session = requ.send(args, session)
            logging.debug("Received code {}".format(code))
            logging.debug("Message: {}".format(r.text))
            if code not in codes:
                codes.append(code)

            if code in ACCEPTED_CODES:
                m.has_request = True
                logging.debug("Good request created {}{}{} {}".format(requ.url.base,
                                                                      requ.url.endpoint, requ.url.parameter,
                                                                      requ.method))

                return requ, codes, session
            else:
                try:
                    requ.use_good_values(good_sets.pop())
                except IndexError:
                    requ.set_dummy_values()
            if code == "401":
                # Expectation is that sometimes this loop logs out/removes the active user/some way breaks its credentials.
                # In these cases we create a new session by setting session = None
                session = None
            if code not in requ.valid_response_codes() and r is not None:
                logging.error("###################")
                logging.error(
                    "Undocumented code {} Valid codes {}\n Sent the following:".format(code, requ.valid_response_codes()))
                logging.error("{} {}".format(r.request.url, r.request.method))
                logging.error(r.headers)
                logging.error(r.request.body)
                logging.error("Received:")
                logging.error(r.headers)
                logging.error(r.text)
                logging.error("###################")


    return False, codes, session


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
    parser.add_argument('-skip', dest='skip',
                        help='Skips specified endpoints. Give endpoints in format ep1,ep2,epx')
    parser.add_argument('-custom_headers', dest='cheader', nargs=2,
                        help='Give a custom header that is used in every request. Give it in format -custom_headers name value')
    parser.add_argument('-allow_http', dest='allow_http', action='store_true',
                        help="Sets os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' allowing the use of http in oauth2")
    parser.add_argument('-validate_chains', dest='validate_chains', action='store_true',
                        help="If true validates each potential chain. Will take a while")
    parser.add_argument('-use_proxy', dest='proxy',
                        help="If you want to run your traffic through a prxy give its address here. Program will set reqeusts librarys"
                             " http, https and ftp proxies to your desired address")
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
    "target_folder": "targets",
    # Current radamsa iteration uses temp folder to store the currently used seed file.
    "temp_folder": "used_cases"
    }
    
    ################

    if args.allow_http:
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'




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

    # Writes the modified json as modified.json.
    #with open('modified.json', 'w') as outfile:
    #    json.dump(api, outfile)

    if str(api.get("openapi")).startswith("3."):
        api = parsers.openapi3(api, args)
    elif str(api.get("openapi")).startswith("2."):
        parsers.openapi2(api)
    else:
        logging.error("Openapi version isn't 2 or 3. Version: "+api.get("openapi"))


    valid_requests = request_generator(api, args)

    # This currently does nothing. Implement chain creation later
    valid_chains, all_chains = create_chains(valid_requests, args)
    if valid_chains is None:
        valid_chains=all_chains

    try:
        fuzz(valid_requests, valid_chains, config, args)
    except KeyboardInterrupt:
        logging.error("Fuzzer was stopped.")




if __name__ == "__main__":
    main()
