import json
from .utils import fetch_content


class OpenIssues(object):

    def __init__(self):
        self.cves = list()
        self.results = dict()
        self.dists = ['trusty', 'xenial', 'yakkety'] #list()

    def refresh(self):
        for cve in sorted(self.cves):
            content = fetch_content(
                'https://api.launchpad.net/devel/bugs/cve/{0}'.format(
                '-'.join(cve.split('-')[1:]))
            )
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
