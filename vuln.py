import os
import PyPDF2
import re
import pandas as pd
from PyPDF2.errors import FileNotDecryptedError

# Đọc các trang từ PDF
def read_pages(pdf_path, start_page, end_page):
    with open(pdf_path, 'rb') as file:
        try:
            pdf_reader = PyPDF2.PdfReader(file)

            if pdf_reader.is_encrypted:
                try:
                    pdf_reader.decrypt('')
                except Exception as e:
                    print(f"Không thể giải mã {pdf_path}: {str(e)}. Bỏ qua...")
                    return None

            text = ""
            for page_num in range(start_page - 1, end_page):
                if page_num < len(pdf_reader.pages):
                    page = pdf_reader.pages[page_num]
                    text += page.extract_text() + "\n"

            return text
        except FileNotDecryptedError:
            print(f"Không thể truy cập các trang trong {pdf_path} do lỗi giải mã. Bỏ qua...")
            return None

# Trích xuất thông tin từ nội dung PDF
def extract_vulnerabilities(text):
    # Regex tìm kiếm số liệu từ mẫu mới, nhận diện số có dấu phẩy
    total = re.search(r'There were ([\d,]+)\s+vulnerabilities found', text)
    critical = re.search(r'(?:([Oo]ne)|([\d,]+))\s+critical vulnerability(?:\s+was found)?|Of these, ([\d,]+)\s+were critical vulnerabilities', text)
    severe = re.search(r'([\d,]+)\s+vulnerabilities were severe', text)
    moderate = re.search(r'([\d,]+)\s+moderate vulnerabilities discovered', text)
    date = re.search(r'Reported on (.*)', text)

    # Hàm chuyển "One" thành số 1 và chuyển chuỗi thành số nguyên
    def convert_to_int(value):
        if value is None:
            return 0
        if isinstance(value, str) and value.lower() == "one":
            return 1
        try:
            # Chuyển chuỗi có dấu phẩy thành số nguyên
            return int(value.replace(',', ''))
        except ValueError:
            return 0

    # Trích xuất và xử lý dữ liệu
    total_count = convert_to_int(total.group(1)) if total else 0

    # Kiểm tra xem nhóm nào từ regex `critical` có giá trị, nếu không thì gán 0
    critical_count = convert_to_int(critical.group(1)) if critical and critical.group(1) else convert_to_int(critical.group(2)) if critical and critical.group(2) else convert_to_int(critical.group(3)) if critical and critical.group(3) else 0
    
    severe_count = convert_to_int(severe.group(1)) if severe else 0
    moderate_count = convert_to_int(moderate.group(1)) if moderate else 0
    report_date = date.group(1) if date else "Không tìm thấy ngày báo cáo"

    return total_count, critical_count, severe_count, moderate_count, report_date

# Trích xuất địa chỉ IP từ tên file
def extract_ip_from_filename(filename):
    match = re.search(r'_(.*?)_', filename)
    return match.group(1) if match else ""

# Xử lý các file PDF trong thư mục
def process_pdfs_in_directory(directory):
    data = []

    for filename in os.listdir(directory):
        if filename.endswith('.pdf'):
            pdf_path = os.path.join(directory, filename)
            print(f"Đang xử lý: {pdf_path}")
            
            tmp = read_pages(pdf_path, 1, 3)
            if tmp is None:
                continue

            total, critical, severe, moderate, report_date = extract_vulnerabilities(tmp)
            ip = extract_ip_from_filename(filename)
            
            data.append({
                'File': filename,
                'IP': ip,
                'Total': total,
                'Critical': critical,
                'Severe': severe,
                'Moderate': moderate,
                'Reported Date': report_date
            })

    df = pd.DataFrame(data)

    output_path = os.path.join(directory, 'vulnerabilities_report.xlsx')
    df.to_excel(output_path, index=False)
    print(f"Dữ liệu đã được ghi vào {output_path}")

# Banner
banner = '''
--------------------------------------------------------------------------------------------------------

██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗██╗   ██╗███╗   ███╗███╗   ███╗ █████╗ ██████╗ ██╗   ██╗
██║   ██║██║   ██║██║     ████╗  ██║    ██╔════╝██║   ██║████╗ ████║████╗ ████║██╔══██╗██╔══██╗╚██╗ ██╔╝
██║   ██║██║   ██║██║     ██╔██╗ ██║    ███████╗██║   ██║██╔████╔██║██╔████╔██║███████║██████╔╝ ╚████╔╝ 
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ╚════██║██║   ██║██║╚██╔╝██║██║╚██╔╝██║██╔══██║██╔══██╗  ╚██╔╝  
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╔╝██║ ╚═╝ ██║██║ ╚═╝ ██║██║  ██║██║  ██║   ██║   
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   
                                                                Create by Vi0l3t
--------------------------------------------------------------------------------------------------------
'''
print(banner)

# Đường dẫn đến thư mục chứa file PDF
path = input("Nhập đường dẫn đến thư mục báo cáo: ").replace("\\", "/")

# Chạy hàm xử lý
process_pdfs_in_directory(path)
