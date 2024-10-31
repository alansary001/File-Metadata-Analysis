import os
import time
import hashlib
import magic
import exifread
import win32security
from PIL import Image
from flask import Flask, render_template, request, send_file

app = Flask(__name__)

# Function to get basic file metadata
def get_file_metadata(file_path):
    try:
        if os.path.exists(file_path):
            file_stats = os.stat(file_path)
            metadata = {
                'File': file_path,
                'Size': file_stats.st_size,  # File size in bytes
                'Last Accessed': time.ctime(file_stats.st_atime),
                'Last Modified': time.ctime(file_stats.st_mtime),
                'File Created': time.ctime(file_stats.st_ctime),
                'Permissions': oct(file_stats.st_mode)[-3:],
                'Owner': get_owner(file_path),
                'File Type': detect_file_type(file_path),  # Detect file type using magic numbers
                'MD5 Hash': calculate_hash(file_path, 'md5'),  # Hashing (MD5)
                'SHA256 Hash': calculate_hash(file_path, 'sha256')  # Hashing (SHA256)
            }
            
            # Check if it's an image file and gather additional image metadata
            if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.tiff', '.bmp', '.gif')):
                image_metadata = get_image_metadata(file_path)
                metadata.update(image_metadata)

            # Check for content scanning in text files
            if file_path.lower().endswith(('.txt', '.csv', '.log')):
                keywords = ['confidential', 'secret', 'password']  # Example keywords to search for
                content_results = scan_file_content(file_path, keywords)
                metadata['Content Scan'] = content_results

            return metadata
        else:
            print(f"File {file_path} does not exist.")
            return None
    except PermissionError:
        print(f"Permission denied for file: {file_path}")
        return None

# Function to get the owner of a file (Windows)
def get_owner(file_path):
    try:
        owner_sid = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION).GetSecurityDescriptorOwner()
        owner_name, domain, type = win32security.LookupAccountSid(None, owner_sid)
        return owner_name
    except Exception as e:
        return "Unknown Owner"

# Function to detect the actual file type using magic numbers
def detect_file_type(file_path):
    file_type = magic.from_file(file_path, mime=True)
    return file_type

# Function to calculate file hash (MD5/SHA256)
def calculate_hash(file_path, algorithm='md5'):
    hash_algo = hashlib.md5() if algorithm == 'md5' else hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_algo.update(chunk)
    return hash_algo.hexdigest()

# Function to scan file content for specific keywords
def scan_file_content(file_path, keywords):
    found_keywords = []
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            for keyword in keywords:
                if keyword.lower() in content.lower():
                    found_keywords.append(keyword)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return found_keywords

# Function to get image-specific metadata, including camera and GPS data
def get_image_metadata(file_path):
    metadata = {}
    try:
        # Extract basic image properties (e.g., width, height, format, etc.)
        with Image.open(file_path) as img:
            metadata['Image Format'] = img.format
            metadata['Image Mode'] = img.mode
            metadata['Image Size'] = img.size  # (width, height)

        # Extract EXIF metadata
        with open(file_path, 'rb') as img_file:
            exif_data = exifread.process_file(img_file, details=False)

            # Extract camera model
            camera_model = exif_data.get('Image Model', 'Unknown Camera')
            metadata['Camera Model'] = str(camera_model)

            # Extract GPS data if available
            gps_info = get_gps_data(exif_data)
            if gps_info:
                metadata.update(gps_info)
    
    except Exception as e:
        metadata['Image Metadata Error'] = str(e)
    
    return metadata

# Function to extract GPS data from EXIF metadata
def get_gps_data(exif_data):
    gps_metadata = {}
    gps_latitude = exif_data.get('GPS GPSLatitude')
    gps_latitude_ref = exif_data.get('GPS GPSLatitudeRef')
    gps_longitude = exif_data.get('GPS GPSLongitude')
    gps_longitude_ref = exif_data.get('GPS GPSLongitudeRef')

    if gps_latitude and gps_latitude_ref and gps_longitude and gps_longitude_ref:
        lat = convert_to_degrees(gps_latitude)
        if gps_latitude_ref.values[0] != 'N':
            lat = -lat

        lon = convert_to_degrees(gps_longitude)
        if gps_longitude_ref.values[0] != 'E':
            lon = -lon

        gps_metadata['GPS Latitude'] = lat
        gps_metadata['GPS Longitude'] = lon
    else:
        gps_metadata['GPS Data'] = 'No GPS data available'

    return gps_metadata

# Function to convert GPS coordinates from EXIF format to degrees
def convert_to_degrees(value):
    d = float(value.values[0].num) / float(value.values[0].den)
    m = float(value.values[1].num) / float(value.values[1].den)
    s = float(value.values[2].num) / float(value.values[2].den)

    return d + (m / 60.0) + (s / 3600.0)

# Function to scan directories recursively
def scan_directory(directory):
    metadata_list = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            metadata = get_file_metadata(file_path)
            if metadata:
                metadata_list.append(metadata)
    return metadata_list

# Function to export metadata to CSV
def export_to_csv(metadata_list, output_file):
    import csv
    if not metadata_list:
        print("No metadata available for export.")
        return

    fieldnames = determine_fieldnames(metadata_list)  # Get dynamic fieldnames
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for metadata in metadata_list:
            writer.writerow(metadata)

# Function to determine dynamic fieldnames for CSV
def determine_fieldnames(metadata_list):
    fieldnames = set()  # Use a set to avoid duplicates
    for metadata in metadata_list:
        fieldnames.update(metadata.keys())  # Add all keys from each metadata dictionary
    return list(fieldnames)  # Convert back to list for CSV writer

# Function to generate a PDF report
def generate_pdf_report(metadata_list, output_file):
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    
    pdf = canvas.Canvas(output_file, pagesize=letter)
    pdf.setTitle("File Metadata Report")
    pdf.drawString(30, 750, "File Metadata Report")
    pdf.drawString(30, 735, "=" * 40)

    y = 700
    for metadata in metadata_list:
        for key, value in metadata.items():
            pdf.drawString(30, y, f"{key}: {value}")
            y -= 15
            if y <= 50:  # Move to the next page if the current page is full
                pdf.showPage()
                y = 750

    pdf.save()

# Route for the main page
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Check if the user uploaded a file or entered a directory
        if 'directory' in request.form and request.form['directory']:
            directory = request.form['directory']
            metadata_list = scan_directory(directory)
        elif 'file' in request.files:  # For single file upload
            file = request.files['file']
            file_path = os.path.join('uploads', file.filename)  # Save file to uploads folder
            file.save(file_path)
            metadata_list = [get_file_metadata(file_path)]

        if not metadata_list:
            return "No files found or insufficient permissions to scan the directory."

        # Export metadata to CSV and PDF
        export_to_csv(metadata_list, 'file_metadata_report.csv')
        generate_pdf_report(metadata_list, 'file_metadata_report.pdf')

        return render_template('results.html', metadata=metadata_list)

    return render_template('index.html')

# Route to download the PDF report
@app.route('/download/<filename>')
def download_file(filename):
    return send_file(filename, as_attachment=True)

# Run the application
if __name__ == '__main__':
    app.run(debug=True)
