import os

CONFIG =  {
    'REDHAT_ADV_URI': 'https://access.redhat.com/labs/' + \
                        'securitydataapi/cvrf.json?per_page=' + \
                        str(os.environ.get('REDHAT_CVRF_COUNT', 2000)),
    'REDHAT_ADV_URL_TEMPLATE': 'https://access.redhat.com/errata/{0}.html',
    'REDHAT_CVE_URL_TEMPLATE': 'https://access.redhat.com/security/cve/{0}',
    'REDHAT_DISTRS': ['el6', 'el7'],

    'UBUNTU_ADV_URI': 'https://usn.ubuntu.com/usn-db/database.pickle.bz2',
    'UBUNTU_CVE_URL_TEMPLATE': 'https://people.canonical.com/' + \
                                '~ubuntu-security/cve/{0}/{1}.html',
    'UBUNTU_USN_URL_TEMPLATE': 'https://www.ubuntu.com/usn/usn-{0}/',
    'LP_BUG_URL': 'https://launchpad.net/bugs/',
    'UBUNTU_DISTRS': ['xenial', 'trusty'],

    'GERRIT_BASE_URL': 'https://review.fuel-infra.org/projects/',
    'GERRIT_PROJECTS': ['trusty', 'xenial', 'centos6', 'centos7'],
    'GERRIT_PROJECTS_MAPPING': {
        'xenial': 'xenial',
        'trusty': 'trusty',
        'el6': 'centos6',
        'el7': 'centos7',
    },

    'CVE_YEARS': [2017, 2016, 2015, 2014, 2013],
}
