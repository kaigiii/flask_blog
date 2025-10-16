from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return 'Hello, World!'

@app.route('/home')
def home():
    return 'Welcome to Home!'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
