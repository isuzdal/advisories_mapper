import json
from .utils import fetch_content


class Packages(object):
    def __init__(self, uri):
        self.packages = dict()
        self.uri = uri
        self.gerrit_projects = list()

    def refresh(self):
        for dist in self.gerrit_projects:
            if dist not in self.packages:
                self.packages[dist] = list()
            uri = self.uri+'?p=packages/{0}'.format(dist)
            info = json.loads(fetch_content(uri)[5:])
            for pkg, pkginfo in info.iteritems():
                if pkginfo['state'] == 'ACTIVE':
                    self.packages[dist].append(pkg.split('/')[-1])

