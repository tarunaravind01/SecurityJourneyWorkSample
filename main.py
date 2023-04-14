from flask import Flask, request, render_template
import subprocess
import re
import os


app = Flask(__name__, template_folder='./template')
app.config['UPLOAD_FOLDER'] = 'uploads'

@app.route('/ping')
def ping_address():
    address = request.args.get('address')
    response = subprocess.getoutput(f"ping -c 3 {address}")
    return render_template('ping.html', result=response)


@app.route('/pingSafe')
def ping_addressSafe():
    render_template('pingSafe.html')
    address = request.args.get('address')
    if address is None:
        address = "8.8.8.8" #default address to ping
    blacklist = [';','cat','&','\n',' ']
    # comprehensiveBlacklist = [';', '&', '|', '>', '<', '$', '(', ')', '#', '*', '\'', '\"', '\\n', '\\r', '\\r\\n']
    # payload = "|\c\a\t${IFS}\/etc\/passwd"
    for i in blacklist:
        if i in address:
            return "Command Injection is no longer allowed"
    response = subprocess.getoutput(f"ping -c 3 {address}")
    if response is not None:  
        return render_template('pingSafe.html', result=response)
    else:
        return "Error: could not ping address"


@app.route('/gift')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    filename = file.filename
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    response = subprocess.getoutput(f"cat ./uploads/{filename}")
    # return render_template('index.html', result=response)
    return "file uploaded successfully and if valid credits will be added to the account"



#this uses regex to sanitize the input
def saniRegex(inputString):
  
    pattern = re.compile(r'^[a-zA-Z0-9\-_.]*$')
    
    if pattern.match(inputString):
        return inputString
    else:
        cleanString = re.sub(r'[^\w\d\-_.]+', '_', inputString)
        return cleanString





if __name__ == '__main__':
    app.run(debug=True)
