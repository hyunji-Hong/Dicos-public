
"""
Post Analyzer Tool.
Author:		Hyunji Hong (hyunji_hong@korea.ac.kr)
Modified: 	September 12, 2021.
"""

import os
import re
import json


"""GLOBALS"""
currentPath	= os.getcwd()       
bigqueryPath = currentPath + '/bigquery_json/'                    # Path with query result json file (from Bigqueiry SOTorrent)
datasetPath = currentPath + '/dataset'
pairingcsPath = datasetPath + '/code_pairs/'
outputPath = currentPath + '/output/'                             # Path of the output files
output_keywordPair = outputPath + 'Analyzing_keyword.json'        # Result of the post descriptions and comments analysis
output_cs = outputPath + 'Analyzing_codesnippet.json'             # Result of the code snippets analysis
output_insecure =  outputPath + 'insecure_posts.txt'              # List of insecure post IDs

# [regex pattern] security-sensitive APIs 
patternAPI_C = re.compile(r'^.*?(strcpy\(|strncpy\(|strcat\(|strncat\(|system\(|memcpy\(|memset\(|malloc\(|gets\(|vfork\(|realloc\(|pthread_mutex_lock\(|free\(|chroot\(|strlen\(|vsprintf\(|sprintf\(|scanf\(|fscanf\(|sscanf\(|vscanf\(|vsscanf\(|vfscanf\(|snprintf\(|atoi\(|strtok\(|strcmp\(|strncmp\(|strcasecmp\(|strncasecmp\(|memcmp\(|signal\(|va_arg\().*$',re.I)
patternAPI_Java = re.compile(r'^.*?(hostnameverifier|trustmanager|sslcontext|cipher|webview|messagedigest|secretkey|keystore|pbekeyspec|ivparameterspec|nextbytes|setseed|signature|keyfactory|connectionspec|sslsocketfactory).*$',re.I)

# [regex pattern] Control-flow change
patternCF = re.compile(r'^.*?(\+if|\+else|\+else if|\+switch|\+case|\-if|\-else|\-else if|\-switch|\-case).*$',re.I)

# [regex pattern] security-related keyword
patternNoun  = re.compile(r'^.*?( vulnerab| fault| defect| sanit| mistake| flaw| bug| hack| infinite| loop| secur| overflow| error| mistake| remote| exploit| mitigat| realloc| heap| privilege| underflow| patch| injection| segment| fault| DoS| denial-of-service| initiali| xss| leak| authentication| authori| attack| out-of-bounds| use-after-free| dereferenc| corruption| crash| memory| NULL| buffer).*$',re.I)
patternVerb = re.compile(r'^.*?( flaw| hack| fix| change| modify| exploit| mitigat| realloc| invoke| inject| ensure| reject| initiali| leak| authori| update| attack| trigger| lock| corrupt| fail| crash| prevent| avoid| access| cause| overflow| terminat).*$',re.I)
patternModifier = re.compile(r'^.*?( incorrect| vulnerab| harm| undefine| unpredict| unsafe| secur| malicious| dangerous| critical| bad| unprivileged| negative| stable| invalid).*$',re.I)

# Generate directories
shouldMake = [datasetPath, outputPath]
for eachRepo in shouldMake:
	if not os.path.isdir(eachRepo):
		os.mkdir(eachRepo)

def Analyze_PostDescription(file):
    # Code for analyzing posts' description.
    # Collect posts containing security-related keyword pairs.
    finishedPosts = []
    descriptionList = []
    result = []

    # For Bigquery json file parsing
    with open(file) as json_file:
        print("[+]Description Analyze:",file)
        lines = json_file.readlines()
        for line in lines:
            json_data  = json.loads(line) 
            if json_data['PostBlockTypeId'] == "1":  
                descriptionList.append([json_data['post_id'],json_data['PostHistoryId'],json_data['Content'],json_data['vote']])

    for data in descriptionList:
        if data[0] in finishedPosts:
            continue

        # To get oldest hisotyId
        postSet = [ _ for _ in descriptionList if _[0] == data[0]]
        postSet = sorted(postSet,key=lambda x:int(x[1])) 
        oldestHistoryID = postSet[0][1]

        # Check if the security-related keyword pairs exist only in diffs
        except_oldest =''.join([ _[2] for _ in postSet if _[1] != oldestHistoryID])
        oldest =''.join([ _[2] for _ in postSet if _[1] == oldestHistoryID])
        splitExcept_oldest = '\n'.join('\n'.join('\n'.join(except_oldest.split('.')).split('!')).split('?'))
        splitOldest = '\n'.join('\n'.join('\n'.join(oldest.split('.')).split('!')).split('?'))

        for l in splitExcept_oldest.split('\n'):
            l = " "+l
            nouns = patternNoun.findall(l)
            modifiers = patternModifier.findall(l)
            verbs = patternVerb.findall(l)
        for l in splitOldest.split('\n'):
            l = " "+l
            nouns = list(set(nouns) - set(patternNoun.findall(l)))
            modifiers = list(set(modifiers) - set(patternModifier.findall(l)))
            verbs = list(set(verbs) - set(patternVerb.findall(l)))

        if len(nouns)> 0 or len(modifiers)> 0:
            if len(verbs)> 0:
                result.append({
                    'postId': data[0],
                    'verb': verbs,
                    'noun': nouns,
                    'modifier': modifiers,
                    'vote' : data[-1],
                    'detectType': 'post'
                })
        finishedPosts.append(data[0]) 
    return result


def Analyze_PostComments(file):
    # Code for analyzing posts' comments.
    # Collect posts containing security-related keyword pairs.
    result = []
    # For Bigquery json file parsing
    with open(file) as json_file:
        print("[+]Comments Analyze:",file)
        lines = json_file.readlines()
        
        for line in lines:
            json_data  = json.loads(line) 
            comment = " "+json_data['comment']
            comment = ''.join(comment.split('\n'))
            splitComment = '\n'.join('\n'.join('\n'.join(comment.split('.')).split('!')).split('?'))
            for l in splitComment.split('\n'):
                nouns = patternNoun.findall(l)
                modifiers = patternModifier.findall(l)
                if len(nouns)> 0 or len(modifiers)> 0:
                    verbs = patternVerb.findall(l)
                    if len(verbs)> 0:
                        result.append({
                            'postId': json_data['post_id'],
                            'verb': verbs,
                            'noun': nouns,
                            'modifier': modifiers,
                            'vote' : json_data['vote'],
                            'detectType': 'comment'
                        })
    return result

def Analyze_CodeSnippet_Java(patchFileName):
    # Code for analyzing JAVA/ANDROID code snippet.
    # Collect posts that contain control-flow changes or security-sensitive APIs.
    result = []
    detect_cf = []
    detect_apis =[]
    with open(pairingcsPath + patchFileName, 'r') as f: data_split = f.read()
    s = re.sub('(---|\+\+\+|@@).*',"",data_split)
    data_split = s.splitlines()
    for line in data_split:
        detect_cf.extend(patternCF.findall(line))
        detect_apis.extend(patternAPI_Java.findall(line))
    if len(detect_cf) > 0 or len(detect_apis) > 0:
        result.append({
            'file_path': patchFileName,
            'cf_change': detect_cf,
            'security-sensitive APIs': detect_apis,
            'patch_diff': ''.join(data_split)
        })

    return result

def Analyze_CodeSnippet_C(patchFileName):    
    # Code for analyzing C/C++ code snippet.
    # Collect posts that contain control-flow changes or security-sensitive APIs.
    result = []
    detect_cf = []
    detect_apis =[]
    with open(pairingcsPath + patchFileName, 'r') as f: data_split = f.read()
    s = re.sub('(---|\+\+\+|@@).*',"",data_split)
    data_split = s.splitlines()
    for line in data_split:
        detect_cf.extend(patternCF.findall(line))
        if line.startswith('-'):
            detect_apis.extend(patternAPI_C.findall(line))
    if len(detect_cf) > 0 or len(detect_apis) > 0:
        result.append({
            'file_path': patchFileName,
            'cf_change': detect_cf,
            'security-sensitive APIs': detect_apis,
            'patch_diff': ''.join(data_split)
        })

    return result


def main():
    input_files        = []
    result_Description = []
    result_Codesnippet = []
    json_obj_key = {'description_keyword': [], 'comment_keyword': []}
    json_obj_cs  = {'code_snippet': []}
    for f in os.listdir(bigqueryPath):
        if f.startswith('comment_'):
            input_comment_file = bigqueryPath + f
        else:
            input_files.append(bigqueryPath+f)

    # Detecting Posts with security-related keyword pairs in the post description and comments.
    for f in input_files:
        result_Description.extend(Analyze_PostDescription(f))
    
    json_obj_key['post_keyword'] = result_Description
    json_obj_key['comment_keyword']= Analyze_PostComments(input_comment_file)
    
    with open(output_keywordPair, "w", encoding='utf-8') as f:
        json.dump(json_obj_key, f)

    # Detecting Posts with security-sensitive APIs or Control Flow change in code snippets
    patchFiles = set([_ for _ in os.listdir(pairingcsPath) if '.diff' in _])
    for file in patchFiles:
        if file.split('_')[-1] == "java":
            result_Codesnippet.extend(Analyze_CodeSnippet_Java(file))
        else:
            result_Codesnippet.extend(Analyze_CodeSnippet_C(file))
    
    json_obj_cs['code_snippet'] = result_Codesnippet

    with open(output_cs, "w", encoding='utf-8') as f:
        json.dump(json_obj_cs, f)
            
    # Combine detecting results
    posts_cf= [_['file_path'].split('_')[0] for _ in json_obj_cs['code_snippet'] if len(_['cf_change']) > 0 ]
    
    posts_apis= [_['file_path'].split('_')[0] for _ in json_obj_cs['code_snippet'] if len(_['security-sensitive APIs']) > 0 ]
    posts_key = [_['postId']for _ in json_obj_key['comment_keyword']]
    posts_key.extend([_['postId']for _ in json_obj_key['post_keyword']])

    insecure_posts = list(set(posts_apis) & set(posts_key)) + list(set(posts_cf) & set(posts_key)) +list(set(posts_apis) & set(posts_cf))

    with open(output_insecure,  "w", encoding='utf-8') as f: 
        f.write("\n".join(set(insecure_posts)))


""" EXECUTE """
if __name__ == "__main__":
	main()