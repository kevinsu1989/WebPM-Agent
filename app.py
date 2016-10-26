from flask import Flask, request
import subprocess
import json
app = Flask(__name__)

@app.route('/')
def main():
    url = request.args.get('url')
    out = subprocess.Popen(['./bin/phantomjs', './netsniff.js', url], stdout=subprocess.PIPE).communicate()[0]

    return out

if __name__ == '__main__':
    app.run(host='0.0.0.0', port='8008')