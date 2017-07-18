import os
REDHAT_CVRF_COUNT = os.environ.get('REDHAT_CVE_COUNT', 2000)
REDHAT_ADV_URI = 'https://access.redhat.com/labs/securitydataapi/cvrf.json?per_page='+str(REDHAT_CVRF_COUNT)

UBUNTU_ADV_URI = 'https://usn.ubuntu.com/usn-db/database.pickle.bz2'

UBUNTU_DISTRS = ['xenial', 'trusty']
REDHAT_DISTRS = ['el6', 'el7']

UBUNTU_CVE_URL_TEMPLATE = 'https://people.canonical.com/~ubuntu-security/cve/{0}/{1}.html'
UBUNTU_USN_URL_TEMPLATE = 'https://www.ubuntu.com/usn/usn-{0}/'
LP_BUG_URL = 'https://launchpad.net/bugs/'

REDHAT_ADV_URL_TEMPLATE = 'https://access.redhat.com/errata/{0}.html'
REDHAT_CVE_URL_TEMPLATE = 'https://access.redhat.com/security/cve/{0}'

GERRIT_BASE_URL = 'https://review.fuel-infra.org/projects/'
GERRIT_PROJECTS = ['trusty', 'xenial', 'centos6', 'centos7']
GERRIT_PROJECTS_MAPPING = {
    'xenial': 'xenial',
    'trusty': 'trusty',
    'el6': 'centos6',
    'el7': 'centos7'
}
