from flask import Flask, request, render_template, redirect, url_for, session
import requests
import time
import statistics
import joblib
from zapv2 import ZAPv2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os
from flask_session import Session
import pandas as pd
import re
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
from flask_cors import CORS


spam_model = joblib.load('D:/spam_classifier.joblib')
url_model = joblib.load('D:/url_classifier.joblib')
vectorizer = joblib.load('D:/vectorizer.joblib')
tfidf_matrix = joblib.load('D:/tfidf_matrix.joblib')
dataset = pd.read_pickle('D:/dataset.pkl')


app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:8000"}})


app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = os.urandom(24)
Session(app)


key = os.urandom(32)
print(f'Encryption key (for testing purposes): {base64.b64encode(key).decode()}')


def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode('utf-8')

def decrypt_data(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data.encode('utf-8'))
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode('utf-8')


class APIPerformanceTester:
    def __init__(self, url, num_requests=10):
        self.url = url
        self.num_requests = num_requests
        self.response_times = []
        self.status_codes = []
        self.response_sizes = []

    def perform_test(self):
        start_test_time = time.time()
        for request_number in range(self.num_requests):
            start_time = time.time()
            try:
                response = requests.get(self.url)
                end_time = time.time()

                response_time = end_time - start_time
                self.response_times.append(response_time)
                self.status_codes.append(response.status_code)
                self.response_sizes.append(len(response.content))
            except requests.exceptions.RequestException as e:
                print(f"Request {request_number + 1} failed: {e}")
                return None
        end_test_time = time.time()

        total_time = end_test_time - start_test_time
        throughput = self.num_requests / total_time

        return {
            "average_response_time": statistics.mean(self.response_times),
            "min_response_time": min(self.response_times),
            "max_response_time": max(self.response_times),
            "stddev_response_time": statistics.stdev(self.response_times),
            "throughput": throughput,
            "status_code_distribution": self._get_status_code_distribution(),
            "error_rate": self._calculate_error_rate(),
            "avg_response_size": statistics.mean(self.response_sizes),
            "num_requests": self.num_requests
        }

    def _get_status_code_distribution(self):
        return {code: self.status_codes.count(code) for code in set(self.status_codes)}

    def _calculate_error_rate(self):
        errors = len([code for code in self.status_codes if code >= 400])
        return (errors / self.num_requests) * 100


def preprocess_text(text):
    text = text.lower()
    text = re.sub(r'\W', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text


def find_similar_vulnerability(description, tfidf_matrix, dataset):
    description_tfidf = vectorizer.transform([description])
    cosine_similarities = cosine_similarity(description_tfidf, tfidf_matrix).flatten()
    most_similar_index = np.argmax(cosine_similarities)
    result = dataset.iloc[most_similar_index].drop('ID')
    return result.to_dict(), cosine_similarities[most_similar_index]


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/spam', methods=['GET', 'POST'])
def index():
    prediction = ""
    if request.method == 'POST':
        email_text = request.form['email']
        if email_text:
            prediction = spam_model.predict([email_text])[0]
            prediction = 'Spam' if prediction == 1 else 'Not Spam'
    return render_template('spam_detector.html', prediction=prediction)

@app.route('/urls', methods=['GET', 'POST'])
def urls_detector():
    prediction = ""
    if request.method == 'POST':
        url_text = request.form['url']
        if url_text:
            prediction = url_model.predict([url_text])[0]
            prediction = 'Malicious' if prediction == 0 else 'Safe'
    return render_template('urls_detector.html', prediction=prediction)

@app.route('/api-security-test', methods=['GET', 'POST'])
def api_test():
    if request.method == 'POST':
        target_url = request.form['api_url']
        zap_proxy = 'http://localhost:8080'
        zap = ZAPv2(proxies={'http': zap_proxy, 'https': zap_proxy})

        print(f'Accessing target {target_url}')
        zap.urlopen(target_url)
        time.sleep(2)

        print(f'Traditional Spidering target {target_url}')
        zap.spider.scan(target_url)
        while int(zap.spider.status()) < 100:
            print(f'Spider progress %: {zap.spider.status()}')
            time.sleep(5)

        print(f'Scanning target {target_url}')
        zap.ascan.scan(target_url)
        while int(zap.ascan.status()) < 100:
            print(f'Ascan progress %: {zap.ascan.status()}')
            time.sleep(5)

        alerts = zap.core.alerts(baseurl=target_url)
        encrypted_alerts = encrypt_data(str(alerts), key)
        session['encrypted_alerts'] = encrypted_alerts
        session['target_url'] = target_url
        return redirect(url_for('display_results'))
    return render_template('api_security_test.html')

@app.route('/results')
def display_results():
    encrypted_alerts = session.get('encrypted_alerts')
    target_url = session.get('target_url')
    if encrypted_alerts:
        decrypted_alerts = eval(decrypt_data(encrypted_alerts, key))
        return render_template('results.html', alerts=decrypted_alerts, target_url=target_url)
    return render_template('results.html', alerts=[], target_url=target_url)

@app.route('/api-performance-test', methods=['GET', 'POST'])
def api_performance_test():
    if request.method == 'POST':
        target_url = request.form['api_url']

        tester = APIPerformanceTester(target_url)
        results = tester.perform_test()

        return render_template('performance_results.html', results=results, target_url=target_url)
    return render_template('api_performance_test.html')

@app.route('/vulnerability-detector', methods=['GET', 'POST'])
def vulnerability_detector():
    if request.method == 'POST':
        input_description = request.form['description']
        input_description = preprocess_text(input_description)
        similar_vulnerability, similarity_score = find_similar_vulnerability(input_description, tfidf_matrix, dataset)
        return render_template('vulnerability_detector.html', input_description=input_description, similar_vulnerability=similar_vulnerability, similarity_score=similarity_score)
    return render_template('vulnerability_detector.html', input_description='', similar_vulnerability=None, similarity_score=None)

if __name__ == '__main__':
    app.run(debug=True)
