import logging
import os,sys
import yaml
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

program_name='process_attack'
program_version='1.2'

def load_config(config_file):
    try:
        with open(config_file,'r') as file:
            try:
                config = yaml.load(file,Loader=yaml.Loader)
                return config
            except yaml.YAMLError as err:
                loggign.error('Read config error: %s',err)
                sys.exit(2)
    except (OSError, IOError) as err:
        logging.error('File error: %s',err)
        sys.exit(2)

base_path = os.path.dirname(sys.argv[0])
config = load_config(base_path + '/config.yml')
config_ip = ''

def set_config_ip(ip):
    config_ip=ip

def get(param):
    return config.get(param)
