import argparse
import json
import yaml
import subprocess
import logging


def ramdasa(amount,testcase_folder,seed_folder):
    
    case_name='fuzzcase'
    output=testcase_folder+'/'+case_name+'-%n'
    
    #Go to testcase_folder, check if files exist, generate files if needed from files in folder seed 
    print subprocess.check_output(['ls',testcase_folder,'|','grep','-q',casename,'|','|','radamsa','-n',output,seed+'/*'])
    
    #Take one of the fuzzcases, use it and then remove it from the pool of files that the above script checks
    #TODO Exact way this is used is not yet decided 
    file_under_use='placeholder.txt'
    print subprocess.check_output(['mv','"$(ls',testcase_folder, '|', 'head','-n 1)"', file_under_use])

def create_folders(folders):
    logging.info('Creating folders')
    #Create all the folders that the program needs for working
    for folder in folders:
        print subprocess.check_output(['mkdir','-p',folder])
        logging.info('Created folder '+folder)
    

def readfile(api):
    #Read yaml or json file        
    logging.info('Reading api file')
    with open(api) as f:
        if api.endswith(".json"):
            data = json.load(f)
        elif api.endswith(".yaml"):
            data = yaml.safe_load(f)
        else:
            logging.warning('Error reading api specification')
            print "Error reading api specification"
    return data
            
def openapi3(api):
    #Parsing of openapi 3.x.x
    print "Api version "+api.get("openapi")
    logging.info("Api version "+api.get("openapi"))
    
    
    
def openapi2(api):
    #TODO Implement a parser for openapi 2.x.x
    print "Api version "+api.get("openapi")
    logging.info("Api version "+api.get("openapi"))
    logging.warning("Version not yet supported")
    print "Not supported yet"


def main():
    #Argparser
    parser = argparse.ArgumentParser(description='Fuzzer')
    parser.add_argument('-api',dest='api', help='OpenApi file', required=True)
    args = parser.parse_args()
    
    logging.basicConfig(filename='log.log',level=logging.DEBUG,format='%(asctime)s %(message)s')

    ####Config######
    #Put these to a file later?
    config={  
    "seed_folder":"seed",
    "testcase_folder":"fuzz_cases",
    "radamsa_output_amount": 1000
    }
   
    ################
    logging.info('Configurations: ')
    for key,val in config.items():
        logging.info(key+":"+str(val))
   
    #If configs dictionary has a variable containing string _folder then create a folder with that name 
    create_folders([value for key, value in config.items() if '_folder' in key.lower()])
    
    api = {}
    api =readfile(args.api)
    
    if str(api.get("openapi")).startswith("3."):
        openapi3(api)
    elif str(api.get("openapi")).startswith("2."):
        openapi2(api)
        
    else:
        logging.warning("Api version not found")



if __name__ == "__main__":
    main()
