import os
import re
import json
import psutil
import time
from cpgqls_client import CPGQLSClient, import_code_query, workspace_query
import Post_Analyzer

"""GLOBALS"""
currentPath	       = os.getcwd()
bigqueryPath       = currentPath + '/bigquery_json/'                    # Path with query result json file (from Bigqueiry SOTorrent)
datasetPath        = currentPath + '/dataset'
pairingcsPath      = datasetPath + '/code_pairs/'       
joernPath	       = "~/bin/joern/joern-cli" 			                # joern-cli path (please specify your own joern path) 
joernWorkspace     = currentPath + '/workspace_joern/'
joernSHfile        = "joern_running.sh"                                 # .sh file with './joern --server' (please specify your own sh file path)
outputPath         = currentPath + '/output/'                           # Path of the output files
output_keywordPair = outputPath + 'Analyzing_keyword.json'              # Result of the post descriptions and comments analysis
output_cs          = outputPath + 'Analyzing_codesnippet.json'          # Result of the code snippets analysis
output_insecure    = outputPath + 'insecure_posts.txt'                  # List of insecure post IDs

# Generate directories
shouldMake = [datasetPath, pairingcsPath, outputPath, joernWorkspace]
for eachRepo in shouldMake:
	if not os.path.isdir(eachRepo):
		os.mkdir(eachRepo)

# [regex pattern] security-related keyword
patternNoun  = re.compile(r'^.*?( vulnerab| fault| defect| sanit| mistake| flaw| bug| hack| infinite| loop| secur| overflow| error| mistake| remote| exploit| mitigat| realloc| heap| privilege| underflow| patch| injection| segment| fault| DoS| denial-of-service| initiali| xss| leak| authentication| authori| attack| out-of-bounds| use-after-free| dereferenc| corruption| crash| memory| NULL| buffer).*$',re.I)
patternVerb = re.compile(r'^.*?( flaw| hack| fix| change| modify| exploit| mitigat| realloc| invoke| inject| ensure| reject| initiali| leak| authori| update| attack| trigger| lock| corrupt| fail| crash| prevent| avoid| access| cause| overflow| terminat).*$',re.I)
patternModifier = re.compile(r'^.*?( incorrect| vulnerab| harm| undefine| unpredict| unsafe| secur| malicious| dangerous| critical| bad| unprivileged| negative| stable| invalid).*$',re.I)

# [regex pattern] security-sensitive APIs 
patternAPI_C = re.compile(r'^.*?(strcpy\(|strncpy\(|strcat\(|strncat\(|system\(|memcpy\(|memset\(|malloc\(|gets\(|vfork\(|realloc\(|pthread_mutex_lock\(|free\(|chroot\(|strlen\(|vsprintf\(|sprintf\(|scanf\(|fscanf\(|sscanf\(|vscanf\(|vsscanf\(|vfscanf\(|snprintf\(|atoi\(|strtok\(|strcmp\(|strncmp\(|strcasecmp\(|strncasecmp\(|memcmp\(|signal\(|va_arg\().*$',re.I)

def joern_process_kill():
    # Code that kills the Joern process.
    for proc in psutil.process_iter(): 
        try:
            processName = proc.name() 
            processID = proc.pid 
            if processName[:6] == "sh":
                commandLine = proc.cmdline() 
                if './joern' in commandLine or joernSHfile in commandLine:
                    parent_pid = processID 
                    parent = psutil.Process(parent_pid)
                    for child in parent.children(recursive=True):
                        child.kill() 
                    parent.kill() 
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess): 
            pass

def joern_process_start():
    # Code that kills the Joern process.
    os.chdir(joernPath)
    os.system(f'nohup -- sh ' + joernSHfile +' &')
    os.chdir(currentPath)
    time.sleep(1)
    

def joern_init():
    # For setting Joern parser
    # ref: https://github.com/ShiftLeftSecurity/cpgqls-client-python
    server_endpoint = "127.0.0.1:8080"
    basic_auth_credentials = ("username", "password")
    client = CPGQLSClient(server_endpoint, auth_credentials=basic_auth_credentials)
    return client

def joern_setting_workspace(client):
    # For setting Joern workspace
    # ref: https://github.com/ShiftLeftSecurity/cpgqls-client-python
    out = workspace_query()
    client.execute(import_code_query(joernWorkspace, "test"))
    client.execute('workspace.setActiveProject("test")')
    client.execute("run.ossdataflow")

def joern_query(client, funcName):
    # Code that executes queries to extract CFG (control flow graph).
    joern_setting_workspace(client)
    pattern = re.compile(r"(res)\d*(: String =)")
    
    # Query for extracting control flow graph
    query = 'cpg.method("'+funcName+'").controlStructure.code.toJsonPretty'
    query_result = client.execute(query)
    cf_result = re.sub(pattern, "", str(query_result['stdout'])).replace("\"\"\"","")
    cf_result = json.loads(cf_result)
    
    # Query for extracting control flow graph - condition 
    query = 'cpg.method("'+funcName+'").controlStructure.condition.code.toJsonPretty'
    query_result = client.execute(query)
    condition_result = re.sub(pattern, "", str(query_result['stdout'])).replace("\"\"\"","")
    condition_result = json.loads(condition_result)
    print([cf_result + condition_result])
    return [cf_result + condition_result]


def joern_workspace(oldest_file, latest_file, funcName):
    # Code that stores only files to be analyzed in a temporary folder.
    # Becuase Joern cannot load many files at once.
    with open(oldest_file, 'r') as f: old_data = f.read()
    with open(latest_file, 'r') as f: lat_data = f.read()
    oldest_tmp = joernWorkspace +  'oldest_tmp.c'
    latest_tmp = joernWorkspace + 'latest_tmp.c'
    with open(oldest_tmp, 'w') as f: 
        f.write(old_data.replace(funcName, 'old_'+funcName))
    with open(latest_tmp, 'w') as f: 
        f.write(lat_data.replace(funcName, 'lat_'+funcName))


def Detect_Control_flow_change(funcName, client):
    # Code for analyzing control flow change in C/C++ code snippet.
    control_flow_change = False

    oldest_query_result = joern_query(client, 'old_'+funcName)
    latest_query_result = joern_query(client, 'lat_'+funcName)

    if set(oldest_query_result) != set(latest_query_result):
       control_flow_change = True

    return control_flow_change


def Analyze_CodeSnippet_C_usingJoern(patchFileName, client):
    # Code for analyzing C/C++ code snippet using Joern parser.
    # Collect posts that contain control-flow changes or security-sensitive APIs.
    funcName = patchFileName.split('_')[2]
    result =[]
    detect_apis = []
    with open(pairingcsPath + patchFileName, 'r') as f: data_split = f.readlines()
    for line in data_split:
        if line.startswith('---'):
            oldest_fileName = line.split('\t')[0].replace("--- ","")
            continue
        elif line.startswith('+++'):
            latest_fileName = line.split('\t')[0].replace("+++ ","")
            continue
        elif line.startswith('-'):
            detect_apis.extend(patternAPI_C.findall(line))
    
    joern_workspace(oldest_fileName, latest_fileName, funcName)

    detect_cf  = Detect_Control_flow_change(funcName, client)

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

    # Restart Joern process 
    client  = joern_init()
    joern_process_kill()
    joern_process_start()
    time.sleep(1)

    json_obj_key = {'description_keyword': [], 'comment_keyword': []}
    json_obj_cs  = {'code_snippet': []}
    for f in os.listdir(bigqueryPath):
        if f.startswith('comment_'):
            input_comment_file = bigqueryPath + f
        else:
            input_files.append(bigqueryPath+f)
    
    # Detecting Posts with security-related keyword pairs in the post description and comments.
    for f in input_files:
        result_Description.extend(Post_Analyzer.Analyze_PostDescription(f))
    
    json_obj_key['post_keyword'] = result_Description
    json_obj_key['comment_keyword']= Post_Analyzer.Analyze_PostComments(input_comment_file)
    
    with open(output_keywordPair, "w", encoding='utf-8') as f:
        json.dump(json_obj_key, f)

    # Detecting Posts with security-sensitive APIs or Control Flow change in code snippets
    diffFiles = set([_ for _ in os.listdir(pairingcsPath) if '.diff' in _])
    for f in diffFiles:
        if f.split('_')[-1] == "java":
            continue
        elif len(f.split('_')) < 4:
            continue
        else:
            result_Codesnippet.extend(Analyze_CodeSnippet_C_usingJoern(f, client))
    
    json_obj_cs['code_snippet'] = result_Codesnippet

    with open(output_cs, "w", encoding='utf-8') as f:
        json.dump(json_obj_cs, f)
            
    # Combine detecting results
    posts_cf= [_['file_path'].split('_')[0] for _ in json_obj_cs['code_snippet'] if _['cf_change']]
    
    posts_apis= [_['file_path'].split('_')[0] for _ in json_obj_cs['code_snippet'] if len(_['security-sensitive APIs']) > 0 ]
    posts_key = [_['postId']for _ in json_obj_key['comment_keyword']]
    posts_key.extend([_['postId']for _ in json_obj_key['post_keyword']])

    insecure_posts = list(set(posts_apis) & set(posts_key)) + list(set(posts_cf) & set(posts_key)) +list(set(posts_apis) & set(posts_cf))

    with open(output_insecure,  "w", encoding='utf-8') as f: 
        f.write("\n".join(set(insecure_posts)))

""" EXECUTE """
if __name__ == "__main__":
	main()