from src.resources import *
import re


class SampleResource(Resource):

    oper_cmd = "show sample"
    oper_cmd_filter = lambda self, name: f'sho sample {name}'
    oper_cmd_brief = "show samples brief"
    config_cmd = "show running sample"
    config_cmd_filter = lambda self, name: f'sho running sample {name}'

    @register('postprocess')
    def postprocess(self, data):
	regular_data = data  # Process leading from data to regular_data
        return regular_data

