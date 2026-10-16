"""Read-only upstream schema checks. Never installs sample data."""
import urllib.request,json,concurrent.futures
urls={
 'RansomLook':'https://www.ransomlook.io/api/groups',
 'MSRC':'https://api.msrc.microsoft.com/cvrf/v3.0/updates',
 'GHSA':'https://api.github.com/advisories?per_page=1',
 'EPSS':'https://api.first.org/data/v1/epss?cve=CVE-2021-44228',
 'NVD':'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228'}
def check(pair):
 name,url=pair
 try:
  req=urllib.request.Request(url,headers={'User-Agent':'Sentinel-Intelligence/0.2','Accept':'application/json'})
  with urllib.request.urlopen(req,timeout=35) as response:data=json.load(response)
  print(name, 'OK',type(data).__name__, 'keys='+str(list(data)[:8]) if isinstance(data,dict) else 'rows='+str(len(data)),flush=True)
 except Exception as e:print(name,'FAILED',str(e),flush=True)
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:list(pool.map(check,urls.items()))
