
"""
Dataset Collection Tool.
Author:		Hyunji Hong (hyunji_hong@korea.ac.kr)
Modified: 	September 11, 2021.
"""

import os
import re
import subprocess
import json

"""GLOBALS"""
currentPath	= os.getcwd()
bigqueryPath = currentPath + '/bigquery_json/'   # Path with query result json file (from Bigqueiry SOTorrent)
datasetPath = currentPath + '/dataset'
csPath = datasetPath + '/code_raw/'          
ctagsPath	= "/usr/local/bin/ctags" 			# Ctags binary path (please specify your own ctags path)


# Generate directories
shouldMake = [datasetPath,bigqueryPath, csPath]
for eachRepo in shouldMake:
	if not os.path.isdir(eachRepo):
		os.mkdir(eachRepo)

def normalize_funcName(string):
    return string.replace(' ','').replace('?','').replace('+','').replace('(','').replace(')','').replace(':','').replace('%','').replace('\"','').replace('[','').replace('^','').replace('<','').replace('>','').replace('*','').replace('-','').replace('&','').replace('!','').replace('|','').replace('.','').replace('$','').replace(']','').replace('\\','')

def ctags_java(file):
    # Code for extracting java method from code snippets.
    # Execute Ctgas command
    try:
        astString = subprocess.check_output(ctagsPath + ' -f - --kinds-java=* --fields=neKS "' + file + '"', stderr=subprocess.STDOUT, shell=True).decode(errors='ignore')
    except subprocess.CalledProcessError as e:
        print("Parser Error:", e)
        astString = ""
    
    # For parsing functions
    f = open(file, 'r', encoding="utf8", errors='ignore')
    lines = f.read()
    result = re.findall(r'(public |private |protected |static )', lines)
    if len(result) ==0:
        return
    lines= lines.splitlines()

    methodList = astString.split('\n')
    method = re.compile(r'(method)')
    number = re.compile(r'(\d+)')
    methodSearch = re.compile(r'{([\S\s]*)}')
    methodlineList = []

    string = ""

    for i in methodList:
        try:
            elemList = re.sub(r'[\t\s ]{2,}', '', i)
            elemList = elemList.split("\t")
            methodBody = ''
            if i != '' and len(elemList) >= 7 and method.match(elemList[3]):
                methodName = elemList[0]
                methodLines = (int(number.search(elemList[4]).group(0)),
                                        int(number.search(elemList[6]).group(0)))
                string = ""
                string = string.join(lines[methodLines[0]-1:methodLines[1]])
                if methodSearch.search(string):
                    methodBody = methodBody + methodSearch.search(string).group(1)
                else:
                    methodBody = " "
                if int(number.search(elemList[4]).group(0))> 2:
                    start = int(number.search(elemList[4]).group(0))-1
                else:
                    start =0 
    
                methodlineList.extend(list((start,int(number.search(elemList[6]).group(0))-1)))
                with open(file.split('.')[0]+'_'+methodName+'.java', 'w', -1, "utf-8") as f: 
                    f.write(string)
        except:
            continue
    
    # Collect code lines that are not extracted as a method
    methodlineList = sorted(methodlineList)
    flag = False
    remainText = []
    for i, line in enumerate(lines):
        if flag == True:
            continue
        if i in methodlineList:
            if flag ==True:
                flag = False
            else:
                flag =True
            continue
        if "package" in line or "import" in line  or "@" in line:
            continue
        else:
            remainText.append(line)
    with open(file,"w") as f:
        f.write(''.join(remainText))   
   
def ctags_c(file):
    # Code for extracting C/C++ function from code snippets.
    # Execute Ctgas command
    try:
        astString = subprocess.check_output(ctagsPath + ' -f - --kinds-C=* --fields=neKSt "' + file + '"', stderr=subprocess.STDOUT, shell=True).decode(errors='ignore')
    except subprocess.CalledProcessError as e:
        print("Parser Error:", e)
        astString = ""

    # For parsing functions
    f = open(file, 'r', encoding="utf8", errors='ignore')
    fileName = file.split('/')[-1]
    lines = f.readlines()
    functionList = astString.split('\n')
    func = re.compile(r'(function)')
    number = re.compile(r'(\d+)')
    funcSearch = re.compile(r'{([\S\s]*)}')
    funclineList = []
    for i in functionList:
        try:
            elemList = re.sub(r'[\t\s ]{2,}', '', i)
            elemList = elemList.split("\t")
            funcBody = ''
            if i != '' and len(elemList) >= 8 and func.fullmatch(elemList[3]):
                funcName  = normalize_funcName(elemList[0])
                funcLines = (int(number.search(elemList[4]).group(0)),
                                        int(number.search(elemList[7]).group(0)))
                string = ""
                string = string.join(lines[funcLines[0]-1:funcLines[1]])
                if funcSearch.search(string):
                    funcBody = funcBody + funcSearch.search(string).group(1)
                else:
                    funcBody = " "
                if int(number.search(elemList[4]).group(0))> 2:
                    start = int(number.search(elemList[4]).group(0))-2
                else:
                    start =0 
                funclineList.extend(list((start,int(number.search(elemList[7]).group(0)))))
                with open(file.split('.')[0]+'_'+funcName+'.'+fileName.split('.')[-1], 'w', -1, "utf-8") as f: 
                    f.write("int main(){\n"+funcBody+"\n}")
        except:
            continue

    # Collect code lines that are not extracted as a function.
    funclineList = sorted(funclineList)
    flag = False
    remainText = []
    for i, line in enumerate(lines):
        if flag == True:
            continue
        if i in funclineList:
            if flag ==True:
                flag = False
            else:
                flag =True
            continue
        if "#" in line:
            continue
        else:
            remainText.append(line)
    with open(file,"w") as f:
        f.write(''.join(remainText)) 


def Collecting_CodeSnippet(file):
    # Code that extracts the oldest and latest versions of code snippets for each post.
    print('[+] parsing Json: ' + file)

    codesnippetList = []
    finishedPosts = []
    
    # For Bigquery json file parsing
    with open(file) as json_file:
        lines = json_file.readlines()
        for line in lines:
            json_data  = json.loads(line) 
            if json_data['PostBlockTypeId'] == "2":  
                codesnippetList.append([json_data['post_id'], json_data['LocalID'],json_data['PostHistoryId'],json_data['Content'],json_data['vote'], json_data['tags'], json_data['date']])

    # Analyze post code snippets
    for item in codesnippetList:
        postID = item[0]
        if "c++" in item[5]:
            ext = ".cpp"
        elif "java" in item[5]:
            ext = ".java"
        elif "android" in item[5]:
            ext = ".java"
        else:
            ext = ".c" 

        if postID in finishedPosts:
            continue

        # To get history of posts    
        postSet = []
        for _ in codesnippetList:
            if _[0] == item[0]:
                postSet.append(_) 
            elif (_[0] != item[0]) and len(postSet) > 0:
                break
            else:
                continue
        
        finishedPosts.append(postID)
        postHistoryId = [_[2] for _ in postSet]

        # Skip if there's no history
        if len(postHistoryId) ==1:
            continue

        # Extract the latest version and the oldest version code snippets.
        # After extracting code snippets, cleaves each snippet into a function/method and other code lines.
        latestVersion  = [_ for _ in postSet if _[2]==postHistoryId[0]]
        oldestVersion  =  [_ for _ in postSet if _[2]==postHistoryId[-1]]

        for i in oldestVersion:
            old_file_name = postID+'_old_'+i[1]+ext
            with open(csPath+old_file_name, 'w', -1, "utf-8") as f: 
                f.write(i[3])
            if ".java" in old_file_name:
                ctags_java(csPath+old_file_name)
            else:
                ctags_c(csPath+old_file_name)

        for i in latestVersion:
            new_file_name = postID+'_new_'+i[1]+ext
            with open(csPath+new_file_name, 'w', -1, "utf-8") as f: 
                f.write(i[3])
            if ".java" in new_file_name:
                ctags_java(csPath+new_file_name)
            else:
                ctags_c(csPath+new_file_name)


def main():
    input_files = []

    for f in os.listdir(bigqueryPath):
        if f.startswith('comment_'):
            continue
        else:
            input_files.append(bigqueryPath+f)
    # Collecting Code snippets 
    for f in input_files:
        Collecting_CodeSnippet(f)


""" EXECUTE """
if __name__ == "__main__":
	main()