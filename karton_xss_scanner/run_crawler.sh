python3 XSStrike/xsstrike.py -u "$1" --console-log-level VULN --crawl -l 2 | sed 's/\x1B[@A-Z\\\]^_]\|\x1B\[[0-9:;<=>?]*[-!"#$%&'"'"'()*+,.\/]*[][\\@A-Z^_`a-z{|}~]//g'
#Regex is used to filter out colors from the output so we can use it as argument to prepare_crawling_result to get urls with potential vulnerabilities.
