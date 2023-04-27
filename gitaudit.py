from os import path
import sys
from datetime import datetime
import logging
import requests
import configparser
import argparse
import json
import yaml
import base64

# Setup/parse command line arguments
argparser = argparse.ArgumentParser()
argparser.add_argument(
    "--config",
    "-c",
    help="Specify alternate config file",
    type=str,
    default="config.ini",
)
argparser.add_argument(
    "--gitenv",
    "-g",
    help="The section of the config file \
        that contains GitHub login information",
    type=str,
    default="git-prod",
)
argparser.add_argument(
    "--level",
    "-l",
    help="Set log level. Accepted values: \
        DEBUG, INFO or WARN. Default value is INFO",
    type=str,
    default="INFO",
)
args = argparser.parse_args()

# Set run date for filename
today = datetime.now()
rundate = today.strftime("%Y-%m-%d-%H-%M")
# Set logfile location as the root of project
ROOT_DIR = path.dirname(path.abspath(__name__))
LOGFILE = f"{ROOT_DIR}/git_audit_{rundate}.log"
# Logging defaults
if args.level.upper() == "DEBUG":
    LOG_LEVEL = logging.DEBUG
    MESSAGE = "Logging set to DEBUG - This will expose secrets in terminal"
elif args.level.upper() == "INFO":
    LOG_LEVEL = logging.INFO
    MESSAGE = "Logging set to INFO - Processes will be explained"
else:
    LOG_LEVEL = logging.WARN
    MESSAGE = "Logging set to WARN - Only warnings and errors will be logged"

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    encoding="utf-8",
    level=LOG_LEVEL
)


def get_logger(args_level) -> logging.Logger:
    logger = logging.getLogger(__name__)
    logger.propagate = False
    if args_level.upper() == "DEBUG":
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(LOG_LEVEL)

    log_format = {
        "severity": "%(levelname)s",
        "message": "%(message)s",
        "logging.googleapis.com/labels": {"label": "github_audit"},
    }
    formatter = logging.Formatter(fmt=json.dumps(log_format))
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    filelogger = logging.FileHandler(LOGFILE)
    fileformat = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    filelogger.setFormatter(fileformat)
    logger.addHandler(filelogger)
    return logger


logger = get_logger(args.level)
logger.info(MESSAGE)
MESSAGE = f"logfile is {LOGFILE}"
logger.info(MESSAGE)

# Read config file
configfile = ROOT_DIR + "/" + (args.config)
log_message = f"Config file being used - {configfile}"
logger.debug(log_message)
config = configparser.ConfigParser()
config.read(configfile)


def git_login():
    """Function to test Github login is working"""
    token = config[args.gitenv]["token"]
    url = "https://api.github.com/user"
    header = {"Authorization": f"token {token}"}
    login_log_message = f"git_login - GitHub token is {token}"
    logger.debug(login_log_message)
    try:
        response = requests.get(url, headers=header)
        response.raise_for_status()
        if response.status_code == requests.codes.ok:
            return "Success"
    except requests.exceptions.RequestException as error:
        logger.critical("git_login - Login failed")
        logger.critical(error)


def get_github_access():
    """Create list of user with access to the named Org"""
    token = config[args.gitenv]["token"]
    org = config[args.gitenv]["org"]
    url = f'https://api.github.com/orgs/{org}/members'
    page = 1
    total_devs = 0
    header = {"Authorization": f"token {token}"}
    params = (
        ("per_page", "100"),
        ("page", page),
    )
    try:
        github_devs = []
        response = requests.get(url, headers=header, params=params)
        r_json = json.loads(response.text)
        response.raise_for_status()
        while response.text != '[]':
            if response.status_code == requests.codes.ok:
                for developer in r_json:
                    dev_name = developer["login"]
                    github_devs.append(dev_name)
                    list_log_message = f"get_github_access - \
Found {dev_name} - Adding to dev list"
                    total_devs += 1
                    logger.info(list_log_message)
                page += 1
                params = (
                    ("per_page", "100"),
                    ("page", page)
                )

                logger.info("Checking for more devs")

                response = requests.get(
                    url,
                    headers=header,
                    params=params
                )

                r_json = json.loads(response.text)
        logger.info("No more members found")
        list_message = f"Total membrs found : {total_devs}"
        logger.info(list_message)
        return github_devs
    except requests.exceptions.RequestException as error:
        logger.error("An error occoured")
        logger.error(error)


def github_read_file(repository_name, file_path):
    headers = {}
    token = config[args.gitenv]["token"]
    headers['Authorization'] = f"token {token}"
    org = config[args.gitenv]["org"]
    url = f'https://api.github.com/repos/{org}/{repository_name}/contents/{file_path}'
    r = requests.get(url, headers=headers)
    r.raise_for_status()
    data = r.json()
    file_content = data['content']
    file_content_encoding = data.get('encoding')
    if file_content_encoding == 'base64':
        file_content = base64.b64decode(file_content).decode()

    return file_content


def find_leavers(userlist):
    leavers = []
    logging.info("Loading developer YAML")
    developers = yaml.safe_load(userlist)['developers']
    dev_usernames = []
    for user in developers:
        dev_usernames.append(user['github_username'])
    logging.info("Checking GitHub members against Developer YAML")
    for user in get_github_access():
        if user not in dev_usernames:
            logging.info(f"Found user not in Developer YAML - {user}")
            leavers.append(user)
    return leavers


def main():
    if git_login() == 'Success':
        try:
            logging.info("Reading developers YAML from GitHub")
            sesame_list = github_read_file(
                config[args.gitenv]['repo'],
                config[args.gitenv]['filepath']
                )
        except Exception as e:
            logging.error(e)
        try:
            logging.info("Checking for leavers")
            leavers = find_leavers(sesame_list)
        except Exception as e:
            logging.error(e)
        for leaver in leavers:
            print(leaver)
