from PyPDF2 import PdfReader
import os
import shutil

keywordsPath = input("Please Enter the complete path of keywords pdf: ")

resumesPath = input("Please Enter the complete path of the resumes folder: ")

reader = PdfReader(keywordsPath)
keywords = []
for page in reader.pages:
    text = page.extract_text()
    text = text.replace(',', ' ')
    keywords.extend(text.split())

keywords = [word.lower() for word in keywords]
print("Selected Resumes:- ")
resumes = [resume for resume in os.listdir(resumesPath) if resume.endswith(".pdf")]
for resume in resumes:
    resumePath = os.path.join(resumesPath, resume)
    reader = PdfReader(resumePath)
    filename = resume
    for page in reader.pages:
        text = page.extract_text()
        text = text.replace(',', ' ')
        content = text.split()
        content = [string.lower().strip() for string in content]
        flag = True
        for word in keywords:
            if word not in content:
                flag = False
                break
        if flag:
            destination_directory = resumesPath + "\\ATS_ApprovedResumes"
            os.mkdir(destination_directory)
            source_path = os.path.join(resumesPath, filename)
            dest_path = os.path.join(destination_directory, filename)
            shutil.copy2(source_path, dest_path)