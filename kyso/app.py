from flask import Flask, request, render_template, send_from_directory
import os
from rsa_utils import sign_data, verify_signature

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


from Crypto.PublicKey import RSA

key = RSA.generate(2048)

with open("my_private.pem", "wb") as f:
    f.write(key.export_key())

with open("my_public.pem", "wb") as f:
    f.write(key.publickey().export_key())

# Tải khóa đã tạo sẵn
with open("my_private.pem", "rb") as f:
    PRIVATE_KEY = f.read()
with open("my_public.pem", "rb") as f:
    PUBLIC_KEY = f.read()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        filename = file.filename
        data = file.read()

        signature = sign_data(data, PRIVATE_KEY)

        with open(os.path.join(UPLOAD_FOLDER, filename), 'wb') as f:
            f.write(data)
        with open(os.path.join(UPLOAD_FOLDER, filename + ".sig"), 'wb') as f:
            f.write(signature)
        with open(os.path.join(UPLOAD_FOLDER, filename + ".pub"), 'wb') as f:
            f.write(PUBLIC_KEY)

        return f"File '{filename}' đã được ký và lưu thành công!"
    return render_template('upload.html')

@app.route('/download')
def download():
    files = os.listdir(UPLOAD_FOLDER)
    return render_template('download.html', files=files)

@app.route('/verify/<basename>')
def verify(basename):
    try:
        file_path = os.path.join(UPLOAD_FOLDER, basename)
        sig_path = file_path + ".sig"
        pub_path = file_path + ".pub"

        with open(file_path, 'rb') as f:
            data = f.read()
        with open(sig_path, 'rb') as f:
            signature = f.read()
        with open(pub_path, 'rb') as f:
            pub_key = f.read()

        result = verify_signature(data, signature, pub_key)
        return f"✅ Chữ ký HỢP LỆ cho file '{basename}'" if result else f"❌ Chữ ký KHÔNG hợp lệ cho file '{basename}'"
    except Exception as e:
        return f"⚠️ Lỗi xác minh: {str(e)}"

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
