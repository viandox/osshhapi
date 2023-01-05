import yaml
from yaml import BaseLoader
import os
import re
import inspect

dir_path = os.path.dirname(os.path.realpath(__file__))
file_path = os.path.join(dir_path, 'models.yml')
models = yaml.load(open(file_path), Loader=BaseLoader)



def register(*args):
    def decorator(f):
        f._register = args
        return f
    return decorator


class Resource:

    def __init__(self, device, raw_data):
        self.device = device
        self._oper_cmd = None
        self._oper_cmd_brief = None
        self._config_cmd = None

        if not self.__class__.__name__ in models.keys():
            raise TypeError('Resource class {} not defined in models'.format(self.__class__.__name__))
        else:
            self.model = models[self.__class__.__name__]
        self._rawdata = raw_data.copy()
        self._init_dyn_references()
        regular_data = self._postprocess(raw_data)
        valid_data = self._validate(regular_data)

        for attribute, value in valid_data.items():
            setattr(self, attribute, value)

    @classmethod
    def _get_registered_methods(cls, flag):
        methods = {method_name: m for method_name, m in inspect.getmembers(cls) if hasattr(getattr(cls, method_name), "_register") and flag in m._register}
        return methods

    @classmethod
    def _get_references(cls, attribute_name):
        methods = {method_name: m for method_name, m in inspect.getmembers(cls) if hasattr(getattr(cls, method_name), "_register") and attribute_name in m._references}
        return methods

    def _init_dyn_references(self):
        methods = self._get_registered_methods(flag="reference")
        for m in methods.values():
            setattr(self.__class__, m.__name__, property(m(self)))

    def _postprocess(self, raw_data):
        methods = self._get_registered_methods(flag="postprocess")
        for m in methods.values():
            raw_data = m(self, raw_data)
        return raw_data

    def _validate(self, raw_data):
        methods = self._get_registered_methods(flag="validate")
        for m in methods.values():
            raw_data = m(self, raw_data)
        return raw_data

    @register('postprocess')
    def postprocess_top(self, data):
        return data  # No postprocessing if not explicitely defined

    @register('validate')
    def validate_top(self, data):
        for attribute, value in self.model.items():
            if attribute in data.keys():
                pass
            else:
                if value.get("type") and value['type'].lower() != "ref":
                    if value.get("required") and value['required'].lower() == "true":
                        if value.get("default"):
                            data[attribute] = value.get("default")
                        else:
                            raise AttributeError('Validation error: Missing required attribute and no default value for {} Resource: {}'.format(self.__class__.__name__, attribute))
                    else:
                        data[attribute] = value.get('default')
            for k, v in data.items():
                try:
                    if self.model[k].get("match_re") and not re.match(self.model[k].get("match_re"), v):
                        raise AttributeError('Validation error: {} value regex mismatch: {}'.format(self.__class__.__name__, attribute))
                except KeyError as e:
                    raise AttributeError('Unknown {} attribute \"{}\", please fix it in models.yml'.format(self.__class__.__name__, k))
        return data

    @property
    def json(self):
        return {k:v for k,v in self.__dict__.items() if k in self.model.keys()}

    def render(self, operation):
        """
        Generating configuration required to add/del Resource
        :param Operation: [add|del]
        :return: Configuration as text
        """
        supported_operations = ['add', 'del']
        if operation not in supported_operations:
            raise ValueError('operation param value not in {}'.format(supported_operations))
        template_filename = '{}.{}.j2'.format(self.__class__.__name__, operation)
        template = self.device.env.get_template(template_filename)
        return template.render(self.json)

    @property
    def running_config(self):
        return self.get_running_config(follow_refs=False)

    def get_running_config(self, follow_refs=False):
        params_names = inspect.getfullargspec(self.config_cmd_filter).args
        params = {arg: getattr(self, arg) for arg in params_names if arg != "self"}
        cmd = self.config_cmd_filter(**params)
        if not cmd:
            raise AttributeError('{} resource has no config_cmd_filter attribute set'.format(self.__class__.__name__))
        config = self.device.exec(cmd)
        if follow_refs:
            for ref in [k for k, v in self.model.items() if v.get('type') == 'ref']:
                config += getattr(self, ref).running_config

        return self.device.strip_config_junk(config)

