import bz2
import bzrlib.branch
import bzrlib.plugin
import cPickle
import datetime
import json
import os
import re
import time
from .utils import fetch_content


class Advisories(object):
    def __init__(self, dist_type, config):
        self.advisories = list()
        self.advinfo = dict()
        self.pkgbase = dict()
        self.cvebase = dict()
        self.uri = config[dist_type]['adv_uri']
        self.dists = config[dist_type]['dists']
        self.bugurl = config[dist_type]['bug_url_tmpl']
        self.cveurl = config[dist_type]['cve_url_tmpl']
        self.advurl = config[dist_type]['adv_url_tmpl']
        self.project_map = config['gerrit']['projects_mapping']
        self.bzrpath = config['bzr']['path']
        self.bzrbranch = config['bzr']['branch']


class UbuntuAdvisories(Advisories):

    def refresh(self):
        archive = bz2.decompress(fetch_content(self.uri))
        self.advisories = cPickle.loads(archive)
        self._fetchBzr()

    def addAdvisoriesInfo(self):
        for adv, advinfo in self.advisories.iteritems():
            if len(set(advinfo['releases'].keys()) & set(self.dists)) > 0:
                info = self._parseAdvEntry(advinfo)
                if not isinstance(info, type(None)):
                    self.advinfo['USN-'+adv] = info

    def _parseAdvEntry(self, advinfo):
        _adv = dict()
        _adv['cves'] = dict()
        _bugs = list()
        bzrdir = os.path.join(self.bzrpath, 'active')

        for cid in advinfo['cves']:
            if self.bugurl in cid:
                cid = 'BUG-' + str(cid.split('/')[-1])
                _adv['cves'][cid] = dict()
                _adv['cves'][cid]['url'] = self.bugurl + cid.split('-')[-1]

            if cid.startswith('CVE'):
                _adv['cves'][cid] = dict()
                _adv['cves'][cid]['url'] = self.cveurl.format(
                                            cid.split('-')[1],
                                            cid)
            if cid in self.cvebase:
                _adv['cves'][cid]['subject'] = self.cvebase[cid]['subject']

                _adv['cves'][cid]['references'] = \
                    self.cvebase[cid]['references']

                _adv['cves'][cid]['commits'] = [
                    l for l in self.cvebase[cid]['references'] if 'commit' in l
                ]

            if os.path.isfile(os.path.join(bzrdir, cid)):
                bugs = self._parseUbuntuCVE(os.path.join(bzrdir, cid))
                if len(bugs) > 0:
                    _bugs += bugs
                
        _adv['packages'] = list()
        for dist in self.dists:
            if dist in advinfo['releases']:
                sources = advinfo['releases'][dist]['sources']
                for pkg, pkginfo in sources.iteritems():
                    if pkg in self.pkgbase[self.project_map[dist]]:
                        epoch, upstream_version, revision, full_version = \
                                        self._parseVersion(pkginfo['version'])
                        _adv['packages'].append(dict({
                            'name': pkg,
                            'epoch': epoch,
                            'upstream_version': upstream_version,
                            'revision': revision,
                            'full_version': full_version,
                            'dist': dist,
                        }))
        _adv['url'] = self.advurl.format(advinfo['id'])
        _adv['known_bugs'] = _bugs
        _adv['timestamp'] = advinfo.get('timestamp', None)
        return _adv if len(_adv['packages']) > 0 else None

    def _parseVersion(self, version):
        try:
            re_valid_version = re.compile(
                r"^((?P<epoch>\d+):)?"
                "(?P<upstream>[A-Za-z0-9:.].+?)"
                "([-+](?P<debian>[A-Za-z0-9+-.~]+))?$")
            v = re_valid_version.match(version)
            epoch = v.group('epoch') if v.group('epoch') is not None else '0'
            revision = v.group('debian')
            upstream_version = v.group('upstream').replace('+dsfg', '')
            return (epoch, upstream_version, revision, version)
        except:
            return (None, None, None, version)

    def _parseUbuntuCVE(self, path):
        bugs = list()
        found = False
        idx = 0
        f = open(path).readlines()
        while idx < len(f):
            l = f[idx]
            if l == 'Bugs:\n':
                found = True
            elif found:
                if l.startswith(' '):
                    bugs.append(l.strip())
                else:
                    break
            idx += 1
        return bugs

    def _fetchBzr(self):
        bzrlib.plugin.load_plugins()
        if not os.path.exists(self.bzrpath):
            os.makedirs(self.bzrpath, mode=0755)
            rb = bzrlib.branch.Branch.open(self.bzrbranch)
            rb.bzrdir.sprout(self.bzrpath).open_branch()
        elif not os.path.isdir(self.bzrpath):
            raise NotADirectoryError
        else:
            rb = bzrlib.branch.Branch.open(self.bzrpath)
            rb.update()
        return True


class RedhatAdvisories(Advisories):

    def refresh(self):
        content = fetch_content(self.uri)
        if len(content) > 0:
            self.advisories = json.loads(content)

    def addAdvisoriesInfo(self):
        for adventry in self.advisories:
            p = [
                x for x in adventry['released_packages'] for
                y in self.dists if x.find(y) > 0
            ]
            if len(p) > 0:
                info = self._parseAdvEntry(adventry)
                if not isinstance(info, type(None)):
                    self.advinfo[adventry['RHSA']] = info

    def _parseAdvEntry(self, adventry):
        _adv = dict()
        _adv['cves'] = dict()
        _adv['packages'] = list()
        _adv['url'] = self.advurl.format(adventry['RHSA'])
        _adv['timestamp'] = None

        _adv['known_bugs'] = [
            self.bugurl.format(bug) for bug in adventry['bugzillas']
        ]

        for cid in adventry['CVEs']:
            _adv['cves'][cid] = dict()
            _adv['cves'][cid]['url'] = self.cveurl.format(cid)

            if cid in self.cvebase:
                _adv['cves'][cid]['subject'] = self.cvebase[cid]['subject']

                _adv['cves'][cid]['references'] = \
                    self.cvebase[cid]['references']

                _adv['cves'][cid]['commits'] = [
                    l for l in self.cvebase[cid]['references'] if 'commit' in l
                ]

        for dist in self.dists:
            for pkg in adventry['released_packages']:
                if dist in pkg:
                    name, epoch, upstream_version, revision, full_version = \
                        self._parseVersion(pkg)

                    if name in self.pkgbase[self.project_map[dist]]:
                        _adv['packages'].append(dict({
                            'name': name,
                            'epoch': epoch,
                            'upstream_version': upstream_version,
                            'revision': revision,
                            'full_version': full_version,
                            'dist': dist
                        }))
        ts_str = adventry.get('released_on', None)
        if ts_str:
            dt_str, offset_str = (ts_str.split('+') + ['00:00', ])[:2]
            offset = offset_str.split(':')
            ts = datetime.datetime.strptime(dt_str, '%Y-%m-%dT%H:%M:%S')\
                 + datetime.timedelta(hours=int(offset[0]),
                                      minutes=int(offset[1]))
            _adv['timestamp'] = time.mktime(ts.timetuple())
        return _adv if len(_adv['packages']) > 0 else None

    def _parseVersion(self, pkg):
        re_valid_version = re.compile(
            "(\S+)-(?:(\d*):)?(.*)-(~?\w+[\w.]*)?(\.(el.*))"
            )
        try:
            name, epoch, upstream_version, revision, _, release = \
                                        re_valid_version.match(pkg).groups()
            if isinstance(epoch, type(None)):
                full_version = '{0}-{1}'.format(upstream_version, revision)
                epoch = '0'
            else:
                full_version = '{0}:{1}-{2}'.format(epoch,
                                                    upstream_version,
                                                    revision)
            return (name, epoch, upstream_version, revision, full_version)
        except:
            return (None, None, None, None, None)

