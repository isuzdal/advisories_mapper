#!/usr/bin/env python
import sys
import json
import config
import lib.packages
import lib.cveinfo
import lib.advisories


def main():
    advs = dict()
    pkgs = lib.packages.Packages(config.CONFIG['GERRIT_BASE_URL'])
    pkgs.gerrit_projects = config.CONFIG['GERRIT_PROJECTS']
    pkgs.refresh()

    cves = lib.cveinfo.CVE(config.CONFIG['CVE_YEARS'])
    cves.refresh()

    ubuntu_advs = lib.advisories.UbuntuAdvisories(config.CONFIG)
    ubuntu_advs.pkgbase = pkgs.packages
    ubuntu_advs.cvebase = cves.cves
    ubuntu_advs.refresh()
    ubuntu_advs.addAdvisoriesInfo()

    redhat_advs = lib.advisories.RedhatAdvisories(config.CONFIG)
    redhat_advs.pkgbase = pkgs.packages
    redhat_advs.cvebase = cves.cves
    redhat_advs.refresh()
    redhat_advs.addAdvisoriesInfo()

    advs.update(ubuntu_advs.advinfo)
    advs.update(redhat_advs.advinfo)

    for adv, advinfo in advs.iteritems():
        x = list()
        for pkg in advinfo['packages']:
            if pkg not in x:
                x.append(pkg)
        advs[adv]['packages'] = x

    if len(sys.argv) > 1:
        with open(sys.argv[1], 'w') as result:
            result.write(json.dumps(advs, indent=2))
    else:
        print(advs)

if __name__ == "__main__":
    main()

