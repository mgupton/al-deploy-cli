"""
Usage:
    al-deploy-cli plan [--global-role-arn=<arn>] [--config-bucket-arn=<config_bucket_arn>] [--aws-account-id=<account_id>] [--appliances=<appliance_type>]
    al-deploy-cli execute [--global-role-arn=<arn>] [--config-bucket-arn=<config_bucket_arn>] [--aws-account-id=<account_id>] [--appliances=<appliance_type>]
Options:
    --appliances=<appliance_type>       (ids|scan|both), default: both
"""

import boto3
from docopt import docopt
from AlertLogicSolution import AlertLogicSolution
import yaml
import json

def main():
    args = docopt(__doc__)
    al_deploy_cli = AlDeployCli(args["--global-role-arn"], args["--config-bucket-arn"], args["--aws-account-id"])

    if args["plan"]:
        al_deploy_cli.deploy_init()
    elif args["execute"]:
        al_deploy_cli.deploy_update()


class AlDeployCli:
    __instance = None
    __auth_token = None
    __config_file = "al-deploy.cfg"
    __local_config_file = "al-deploy-local.cfg"
    __global_role_policy_name = "al-deploy-cli-global"
    __global_role_arn = None
    __global_role_name = None
    __config_bucket = None
    __config_bucket_region = None
    __config = {}
    __aws_account_id = None
    
    __aws_access_key = None
    __aws_secret_key = None
    __aws_session_token = None
    __aws_session = None

    __target_aws_access_key = None
    __target_aws_secret_key = None
    __target_aws_session_token = None
 
    @staticmethod
    def get_instance():
        if AlDeployCli.__instance is None:
            AlDeployCli()
        return AlDeployCli.__instance
 
    def __init__(self, global_role_arn, config_bucket_arn, aws_account_id):
        if AlDeployCli.__instance != None:
            raise Exception("This class is a singleton!")
        else:
            AlDeployCli.__instance = self
            AlDeployCli.__global_role_arn = global_role_arn
            AlDeployCli.__config_bucket = config_bucket_arn

            AlDeployCli.__aws_account_id = aws_account_id

            self.load_local_config()
            self.assume_global_role()
            self.load_config()
            self.get_target_account_role(self.__aws_account_id)
    
    def assume_global_role(self):

        self.__aws_session = boto3.Session(profile_name='al-deploy-cli-global')
        sts = self.__aws_session.client('sts')
        sts = sts.assume_role(RoleArn=self.__global_role_arn, RoleSessionName="AlDeployCli")

        self.__aws_access_key = sts["Credentials"]["AccessKeyId"]
        self.__aws_secret_key = sts["Credentials"]["SecretAccessKey"]
        self.__aws_session_token = sts["Credentials"]["SessionToken"]

        self.__aws_session = boto3.Session(
            aws_access_key_id=self.__aws_access_key,
            aws_secret_access_key=self.__aws_secret_key,
            aws_session_token=self.__aws_session_token,
        )


    def load_local_config(self):
        with open(self.__local_config_file) as file:
            local_cfg = yaml.load(file, Loader=yaml.FullLoader)

        if self.__global_role_arn == None:
            if local_cfg["global-role-arn"] != None:
                self.__global_role_arn = local_cfg["global-role-arn"]
            else:
                raise RuntimeError()

        if self.__config_bucket == None:
            if local_cfg["config-bucket-name"] != None:
                self.__config_bucket = local_cfg["config-bucket-name"]
            else:
                raise RuntimeError()

        if self.__config_bucket_region == None:
            if local_cfg["config-bucket-region"] != None:
                self.__config_bucket_region = local_cfg["config-bucket-region"]
            else:
                raise RuntimeError()

    def load_config(self):
        # s3_client = boto3.client('s3', region_name=self.__config_bucket_region,
        #    aws_access_key_id = self.__aws_access_key,
        #    aws_secret_access_key = self.__aws_secret_key,
        #    aws_session_token = self.__aws_session_token
        # )

        s3_client = self.__aws_session.client('s3', region_name=self.__config_bucket_region)

        obj = s3_client.get_object(Bucket=self.__config_bucket, Key=self.__config_file)
        file_data = obj['Body'].read()
        contents = file_data.decode('utf-8')
        
        self.__config = yaml.load(contents, Loader=yaml.FullLoader)

        al_api_access = self.get_secret(self.__config["al-api-access"]["al-api-secrets-id"],
            self.__config["al-api-access"]["al-api-secrets-region"])
        self.__config["al-api-access"]["access_key"] = al_api_access["al_access_key"]
        self.__config["al-api-access"]["secret_key"] = al_api_access["al_secret_key"]


    def get_secret(self, secret_id, secret_region):
        client = boto3.client(
            service_name='secretsmanager',
            region_name=secret_region,
            aws_access_key_id = self.__aws_access_key,
            aws_secret_access_key = self.__aws_secret_key,
            aws_session_token = self.__aws_session_token
        )

        secret_json = client.get_secret_value(SecretId=secret_id)

        secret = json.loads(secret_json['SecretString'])

        return secret

    def get_specified_scope(self):
        pass

    def get_configured_scope(self):
        pass

    def get_target_account_role(self, aws_account_id):
        iam_client = self.__aws_session.client('iam')

        for role in iam_client.list_roles()['Roles']:
            if role['Arn'] == self.__global_role_arn:
                self.__global_role_name = role['RoleName']
                break

        policy = iam_client.get_role_policy(RoleName=self.__global_role_name, PolicyName=self.__global_role_policy_name)

        for i, statement in enumerate(policy["PolicyDocument"]["Statement"]):
            if statement["Action"] == "sts:AssumeRole":
                for role_arn in policy["PolicyDocument"]["Statement"][i]["Resource"]:
                    print(role_arn)
        pass

    @staticmethod
    def deploy_init():
        pass
    
    @staticmethod
    def deploy_update():
        pass

    @staticmethod
    def get_target_account_role():
        pass

    @staticmethod
    def get_al_api_credentials():
        pass
    
    @staticmethod
    def get_deployment_config():
        pass


if __name__ == "__main__":
    main()
