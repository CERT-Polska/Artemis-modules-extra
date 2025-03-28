python3 XSStrike/xsstrike.py -u $1 --console-log-level VULN --crawl -l 1 | sed 's/\x1B[@A-Z\\\]^_]\|\x1B\[[0-9:;<=>?]*[-!"#$%&'"'"'()*+,.\/]*[][\\@A-Z^_`a-z{|}~]//g' 
