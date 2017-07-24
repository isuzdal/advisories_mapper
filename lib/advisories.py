import urllib2
import cPickle
import bz2
import json
import urllib2
import re


class Advisories(object):
    def __init__(self):
        self.advisories = list()
        self.advinfo = dict()
        self.pkgbase = dict()
        self.cvebase = dict()


class UbuntuAdvisories(Advisories):
    def __init__(self, config):
        self.uri = config['UBUNTU_ADV_URI']
        self.dists = config['UBUNTU_DISTRS']
        self.bugurl = config['LP_BUG_URL']
        self.cveurl = config['UBUNTU_CVE_URL_TEMPLATE']
        self.advurl = config['UBUNTU_USN_URL_TEMPLATE']
        self.project_map = config['GERRIT_PROJECTS_MAPPING']
        super(UbuntuAdvisories, self).__init__()

    def refresh(self):
        archive = bz2.decompress(urllib2.urlopen(self.uri).read())
        self.advisories = cPickle.loads(archive)

    def addAdvisoriesInfo(self):
        for adv, advinfo in self.advisories.iteritems():
            if len(set(advinfo['releases'].keys()) & set(self.dists)) > 0:
                info = self._parseAdvEntry(advinfo)
                if not isinstance(info, type(None)):
                    self.advinfo['USN-'+adv] = info

    def _parseAdvEntry(self, advinfo):
        _adv = dict()
        _adv['cves'] = dict()
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


class RedhatAdvisories(Advisories):
    def __init__(self, config):
        self.uri = config['REDHAT_ADV_URI']
        self.dists = config['REDHAT_DISTRS']
        self.cveurl = config['REDHAT_CVE_URL_TEMPLATE']
        self.advurl = config['REDHAT_ADV_URL_TEMPLATE']
        self.project_map = config['GERRIT_PROJECTS_MAPPING']
        super(RedhatAdvisories, self).__init__()

    def refresh(self):
        self.advisories = json.loads(urllib2.urlopen(self.uri).read())

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

