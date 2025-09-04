from flask import Flask, render_template, send_from_directory, request, make_response

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/static/poc/malicious.txt')
def serve_malicious():
    response = make_response(send_from_directory('static/poc', 'malicious.txt'))
    if request.args.get('nosniff') == 'true':
        response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

if __name__ == '__main__':
    app.run(debug=True)