from PyPDF2 import PdfReader
from pathlib import Path
import os
import shutil

keywordsPath = "Python\\Mini-ATS\\TestData\\Keywords.pdf"

resumesPath = "Python\\Mini-ATS\\TestData\\CVs"

try:
    percentage = int(input("Please enter percentage of keywords to match in CVs(Integer only): "))
except Exception as e:
    print(f"Error: {e}")
    exit(1)

reader = PdfReader(keywordsPath)
keywords = []
for page in reader.pages:
    text = page.extract_text()
    text = text.replace(',', ' ')
    keywords.extend(text.split())

n = len(keywords)

keywords = [word.lower() for word in keywords]
resumes = [resume for resume in os.listdir(resumesPath) if resume.endswith(".pdf")]
for resume in resumes:
    resumePath = os.path.join(resumesPath, resume)
    reader = PdfReader(resumePath)
    filename = resume
    count = 0
    for page in reader.pages:
        text = page.extract_text()
        text = text.replace(',', ' ')
        content = text.split()
        content = [string.lower().strip() for string in content]
        flag = True
        for word in keywords:
            if word in content:
                count += 1
        if ((count / n) * 100) >= percentage:
            destination_directory = resumesPath + "\\ATS_ApprovedResumes"
            if not Path(destination_directory).is_dir():
                os.mkdir(destination_directory)
            source_path = os.path.join(resumesPath, filename)
            dest_path = os.path.join(destination_directory, filename)
            shutil.copy2(source_path, dest_path)
