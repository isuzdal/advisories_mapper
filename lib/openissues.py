import json
from .utils import fetch_content


class OpenIssues(object):

    def __init__(self,config):
        self.cves = list()
        self.results = dict()
        self.uri = config.get('cve_uri_template', str())
        self.dists = config.get('dists', list())
        self.mapping = config.get('mapping', dict())

class UbOpenIssues(OpenIssues):

    def refresh(self):
        for cve in sorted(self.cves):
            content = fetch_content(self.uri.format(
                        '-'.join(cve.split('-')[1:])))

            a = json.loads(content) if len(content) > 0 else dict()

            body = fetch_content(a.get('bugs_collection_link', str()),tmout=20)

            bugs = json.loads(body) if len(body) > 0 else dict()

            for bug in bugs.get('entries', list()):
                taskurl = bug.get('bug_tasks_collection_link', str())
                b = fetch_content(taskurl,tmout=20)
                tasks = json.loads(b) if len(b) > 0 else dict()
                for task in tasks.get('entries', list()):
                    if not task.get('is_complete', False):
                        url = task['web_link']
                        # Skip issues without distribution "pointer"
                        #if not '/+source/' in url:
                        if not url.count('/') == 8:
                            continue
                        pkg_info = url.split('/')
                        dist = pkg_info[4]
                        pkg_src_name = pkg_info[6]
                        bug_id = pkg_info[8]

                        if dist in self.dists:
                            if cve not in self.results:
                                self.results[cve] = dict()
                            if dist not in self.results[cve]:
                                self.results[cve][dist] = dict()
                            if pkg_src_name not in self.results[cve][dist]:
                                self.results[cve][dist][pkg_src_name] = dict()
                            self.results[cve][dist][pkg_src_name][bug_id] = url


class RhOpenIssues(OpenIssues):

    def _mapping(self, cpe):
        if cpe == str():
            return None
        _cpe = cpe.split('/')[1].split(':')[1:]
        if len(_cpe) == 3:
            vendor, family, version = _cpe
        elif len(_cpe) == 5:
            vendor, family, version, _, dist = _cpe
        if family in self.mapping:
            return self.mapping.get(family, dict()).get(version, None)
        return None

    def refresh(self):
        for cve in self.cves:
            body = fetch_content(self.uri.format(cve))
            if len(body) > 0:
                data = json.loads(body)
                #if data.get('threat_severity', 'low').lower() == 'low':
                #    continue
                cpes = data.get('package_state', list())
                if isinstance(cpes, dict):
                    cpes = [cpes]
                for cpe in cpes:
                    _cpe = self._mapping(cpe.get('cpe', str()))
                    if _cpe in self.dists:
                        if cpe['fix_state'] == 'Will not fix':
                            continue
                        if cpe['fix_state'] == 'Not affected':
                            continue
                        if cve not in self.results:
                            self.results[cve] = dict()
                            self.results[cve]['packages'] = dict()
                        if _cpe not in self.results[cve]:
                            self.results[cve]['packages'][_cpe] = dict()
                        self.results[cve]['packages'][_cpe]\
                                    [cpe['package_name']]= cpe['fix_state']
                if cve in self.results:
                    self.results[cve]['url'] = data.get('bugzilla', dict()
                                                    ).get('url', str())
