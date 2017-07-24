import urllib2
from xml.dom import minidom


class CVE(object):
    def __init__(self, years):
        self.years = list(years)
        self.cves = dict()
        self.xmldata = str()
        self.uri_tmpl = 'http://cve.mitre.org/data/downloads/' + \
                        'allitems-cvrf-year-{0}.xml'

    def _fetchData(self, year):
        self.xmldata = urllib2.urlopen(self.uri_tmpl.format(year)).read()

    def _parseAndUpdate(self):
        xmldata = minidom.parseString(self.xmldata)
        vulnerabilities = xmldata.getElementsByTagName('Vulnerability')
        for vuln in vulnerabilities:
            reflist = list()
            subj = str()
            if vuln.getElementsByTagName('CVE')[0].hasChildNodes():
                cid = vuln.getElementsByTagName('CVE')[0].firstChild.data
                for refs in vuln.getElementsByTagName('References'):
                    for ref in refs.getElementsByTagName('Reference'):
                        for url in ref.getElementsByTagName('URL'):
                            if url.hasChildNodes():
                                reflist.append(str(url.firstChild.data))
                note = vuln.getElementsByTagName('Notes')[0]
                if note.getElementsByTagName('Note')[0].hasChildNodes():
                    subj = note.getElementsByTagName('Note')[0].firstChild.data
                if cid not in self.cves:
                    self.cves[cid] = dict()
                    self.cves[cid]['references'] = list()
                    self.cves[cid]['subject'] = str()
                self.cves[cid]['references'] = reflist
                self.cves[cid]['subject'] = subj

    def refresh(self):
        for year in self.years:
            self._fetchData(year)
            self._parseAndUpdate()

