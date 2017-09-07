from .utils import fetch_content
import json
import multiprocessing.dummy
import os
import zlib


class CVE(object):
    def __init__(self, years):
        self.years = list(years)
        self.cves = dict()
        self.xmldata = str()
        self.uri_tmpl = 'https://static.nvd.nist.gov/feeds/json/cve' + \
                        '/1.0/nvdcve-1.0-{0}.json.gz'

    def _fetchAndProcess(self, year):
        content = fetch_content(self.uri_tmpl.format(year))
        if not len(content) == 0:
            content = json.loads(zlib.decompress(content, zlib.MAX_WBITS|32))
            self._process(content['CVE_Items'])
        return True

    def _process(self, cves):
        for cve in cves:
            cid = cve['cve']['CVE_data_meta']['ID']
            desc = cve['cve']['description']['description_data'][0]['value']
            refs = cve['cve'].get('references', {}).get('reference_data', list())
            self.cves[cid] = dict()
            self.cves[cid]['subject'] = desc
            self.cves[cid]['references'] = [str(i['url']) for i in refs]
        return True

    def refresh(self):
        THR_COUNT = len(self.years)
        pool = multiprocessing.dummy.Pool(THR_COUNT)
        pool.map_async(self._fetchAndProcess, self.years)
        pool.close()
        pool.join()
        pool.terminate()

