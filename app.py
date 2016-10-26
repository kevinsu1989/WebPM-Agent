import subprocess
import json
out = subprocess.Popen(['phantomjs', './netsniff.js', 'http://www.mgtv.com/beta/'], stdout=subprocess.PIPE).communicate()[0]

print out