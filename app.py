#!/usr/bin/env python
import argparse
import json
import yaml
import sys
import lib.packages
import lib.cveinfo
import lib.advisories
import lib.openissues


def main():
    parser = argparse.ArgumentParser(description='No description.')
    parser.add_argument('-c', '--config',
                        default='config.yaml', dest='config',
                        action='store', help='%(prog)s config path')
    parser.add_argument('-o', '--output', default='STDOUT',
                        dest='output', action='store', help='output, can be STDOUT or path to file')
    parser.add_argument('-u', '--unresolved',
                        action='store_true', dest='unresolved',
                        help='Collect all bugs which referenced to CVEs and still are open. ' \
                        'Attention, it takes a LOT of time!')
    args = parser.parse_args()

    advs = dict({'resolved': dict(), 'active': dict()})

    config = yaml.safe_load(open(args.config, 'r').read())

    pkgs = lib.packages.Packages(config['gerrit']['base_uri'])
    pkgs.gerrit_projects = config['gerrit']['projects']
    pkgs.refresh()

    cves = lib.cveinfo.CVE(config['cve']['years'])
    cves.refresh()

    ubuntu_advs = lib.advisories.UbuntuAdvisories('debian', config)
    ubuntu_advs.pkgbase = pkgs.packages
    ubuntu_advs.cvebase = cves.cves
    ubuntu_advs.refresh()
    ubuntu_advs.addAdvisoriesInfo()

    redhat_advs = lib.advisories.RedhatAdvisories('redhat', config)
    redhat_advs.pkgbase = pkgs.packages
    redhat_advs.cvebase = cves.cves
    redhat_advs.refresh()
    redhat_advs.addAdvisoriesInfo()

    advs['resolved'].update(ubuntu_advs.advinfo)
    advs['resolved'].update(redhat_advs.advinfo)

    for adv, advinfo in advs['resolved'].iteritems():
        x = list()
        for pkg in advinfo['packages']:
            if pkg not in x:
                x.append(pkg)
        advs['resolved'][adv]['packages'] = x

    if args.unresolved:
        issues = lib.openissues.OpenIssues()
        issues.cves = cves.cves
        issues.dists = config['debian']['dists']
        issues.refresh()
        advs['active'] = issues.results

    res = json.dumps(advs, indent=2)

    if args.output is not 'STDOUT':
        with open(args.output, 'w') as result:
            result.write(res)
    else:
        print(res)

if __name__ == "__main__":
    # Ensure what python2 is used, due to bzr doesn't have python3 support
    assert sys.version_info.major == 2
    main()
