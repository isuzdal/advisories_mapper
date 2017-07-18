#!/usr/bin/env python
import sys
import json
import config
import lib.packages
import lib.cveinfo
import lib.advisories

def main():
    advs = dict()
    # { advid: { cves: {id: {url: url, subj: subj}}},
    #           packages: [{name: spkg_name, dist: dist, source_ver: upstream_version,
    #                       revision: revision, full_version: full_version}],
    #           subject: subject,
    #           urls: []
    pkgs = lib.packages.Packages(config.GERRIT_BASE_URL)
    pkgs.gerrit_projects = config.GERRIT_PROJECTS
    pkgs.refresh()

    cves = lib.cveinfo.CVE([2017, 2016, 2015, 2014, 2013])
    cves.refresh()

    ubuntu_advs = lib.advisories.UbuntuAdvisories(config.UBUNTU_ADV_URI)
    ubuntu_advs.dists = config.UBUNTU_DISTRS
    ubuntu_advs.bugurl = config.LP_BUG_URL
    ubuntu_advs.cveurl = config.UBUNTU_CVE_URL_TEMPLATE
    ubuntu_advs.advurl = config.UBUNTU_USN_URL_TEMPLATE
    ubuntu_advs.project_map = config.GERRIT_PROJECTS_MAPPING
    ubuntu_advs.pkgbase = pkgs.packages
    ubuntu_advs.cvebase = cves.cves
    ubuntu_advs.refresh()
    ubuntu_advs.addAdvisoriesInfo()

    redhat_advs = lib.advisories.RedhatAdvisories(config.REDHAT_ADV_URI)
    redhat_advs.dists = config.REDHAT_DISTRS
    redhat_advs.cveurl = config.REDHAT_CVE_URL_TEMPLATE
    redhat_advs.advurl = config.REDHAT_ADV_URL_TEMPLATE
    redhat_advs.project_map = config.GERRIT_PROJECTS_MAPPING
    redhat_advs.pkgbase = pkgs.packages
    redhat_advs.cvebase = cves.cves
    redhat_advs.refresh()
    redhat_advs.addAdvisoriesInfo()

    advs.update(ubuntu_advs.advinfo)
    advs.update(redhat_advs.advinfo)

    for adv,advinfo in advs.iteritems():
        x = list()
        for pkg in advinfo['packages']:
            if not pkg in x:
                x.append(pkg)
        advs[adv]['packages'] = x

    if len(sys.argv) > 1:
        with open(sys.argv[1], 'w') as result:
            result.write(json.dumps(advs,indent=2))
    else:
        print(advs)

if __name__ == "__main__":
    main()
