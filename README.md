#FuzzManagerCollector

> [FuzzManager](https://github.com/MozillaSecurity/FuzzManager) client library, easy to submit crash.


## Example

```python
stdout = None
stderr = None
crashdata = None
crashInfo = None
args = None
env = None
metadata = {}
product = 'test_product'
platform = 'x86'
os = 'linux'
product_version = '1.0'
testcase = '/tmp/a.js'
stdout = 'test_stdout'
stderr = 'test_stderr'
crashdata = 'test_crashdata'
testcasequality = 0
tool = 'test_tool'
# metadata = 'test_metadata'

configuration = ProgramConfiguration(product, platform,
                                        os, product_version,
                                        env, args, metadata)


crashInfo = CrashInfo.fromRawCrashData(stdout, stderr, configuration, auxCrashData=crashdata)
if testcase:
    (testCaseData, isBinary) = Collector.read_testcase(testcase)
    if not isBinary:
        crashInfo.testcase = testCaseData

collector = Collector(sigCacheDir='/tmp/sigcache', tool=tool)


collector.submit(crashInfo, testcase, testcasequality)
```
