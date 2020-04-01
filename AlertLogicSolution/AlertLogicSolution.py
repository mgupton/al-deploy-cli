


class AlertLogicSolution:
    """"""
    __instance = None
    __auth_token = None
 
    """"""
    @staticmethod
    def get_instance():
        if AlertLogicSolution.__instance is None:
            AlertLogicSolution()
        return AlertLogicSolution.__instance
 
    def __init__(self):
        if AlertLogicSolution.__instance != None:
            raise Exception("This class is a singleton!")
        else:
            AlertLogicSolution.__instance = self

    @staticmethod
    def authenticate():
        pass

    @staticmethod
    def get_deployment_config():
        pass
