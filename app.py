from flask import Flask, request
import subprocess
import json
app = Flask(__name__)

@app.route('/')
def main():
    url = request.args.get('url')
    method = request.args.get('method') or 'netsniff'
    out = subprocess.Popen(['./bin/phantomjs', './src/' + method + '.js', url], stdout=subprocess.PIPE).communicate()[0]

    return out



@app.route('/update')
def update():
    url = request.args.get('url')
    path = request.args.get('path') or './src'
    os.system('./shell/update.sh ' + url + ' ' + path)

    return 'done'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port='8008')