import importlib
import os
import re

try:
    from apps import enabled as a_mod
    from training import enabled as t_mod
except:
    try:
        from server.apps import enabled as a_mod
        from server.training import enabled as t_mod
    except:
        raise Exception('Could Not Load Traingin Data...')


class loader(object):
    def __init__(self):
        self.app_map = {}
        self.modules = []
        self.training = []

    def load_modules(self, path):
        pysearchre = re.compile('^[^__].+.py$', re.IGNORECASE)
        pluginfiles = filter(pysearchre.search, os.listdir(os.path.join(os.path.dirname(__file__), path[0])))
        form_module = lambda fp: '.' + os.path.splitext(fp)[0]
        plugins = map(form_module, pluginfiles)
        for plugin in plugins:
            if not plugin.startswith('__'):
                if "apps" in path[0]:
                    self.modules.append(importlib.import_module(plugin, package=a_mod.__name__))
                else:
                    # importlib.import_module("..training_data")
                    self.training.append(importlib.import_module(plugin, package=t_mod.__name__))

    def load_apps(self):
        self.load_modules(a_mod.__path__)
        self.app_mapper()

    def load_training_data(self):
        self.load_modules(t_mod.__path__)
        return self.training

    def app_mapper(self):
        for i in self.modules:
            try:
                app = i.Main()

                try:
                    if app.default_app == True:
                        pass
                except:
                    app.default_app = False

                self.app_map[i.__name__] = app
            except BaseException as e:
                raise e


if __name__ == "__main__":
    x = loader()
    x.load_apps()
    z = x.load_training_data()
    print x.app_map
    print z
