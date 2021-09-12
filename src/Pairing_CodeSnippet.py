

"""
Code Snippet Pairing Tool.
Author:		Hyunji Hong (hyunji_hong@korea.ac.kr)
Modified: 	September 12, 2021.
"""

import os
import re
import shutil
from itertools import product


"""GLOBALS"""
currentPath	= os.getcwd()
datasetPath = currentPath + '/dataset'
csPath = datasetPath + '/code_raw/'
pairingcsPath = datasetPath + '/code_pairs/'

# Generate directories
shouldMake = [datasetPath, csPath, pairingcsPath]
for eachRepo in shouldMake:
	if not os.path.isdir(eachRepo):
		os.mkdir(eachRepo)

def removeComment(string):
    # Code for removing C/C++, Java style comments. (Imported from VUDDY and ReDeBug.)
	# ref: https://github.com/squizz617/vuddy
	c_regex = re.compile(
		r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
		re.DOTALL | re.MULTILINE)
	return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])

def diffing(f, f_new):
    # Code for extracting diffs between the paired code snippets.
    diffFileName = f.replace('_old_','_').replace('.','_')+'.diff'
    diffCommand = f'diff -u {f} {f_new} >> {diffFileName}'
    os.system(diffCommand +" 2>nul")
    return diffFileName


def jaccard_similarity(s1, s2):
    # Code for measuring similarities between code snippets.
    s1 = set(s1) 
    s2 = set(s2)
    return len(s1 & s2) / len(s1 | s2)


def Pairing_Codesnippet(postId):
    # Code for code snippet pairing. 
    theta = 0.3     # jaccard similarity threshold
    jaccard_result = []
    # Check the similarity of all snippets between the oldest and latest versions. 
    post_snippets = [[_ for _ in os.listdir(csPath) if _.split('_')[0]==postId and '_old' in _] , [_ for _ in os.listdir(csPath) if _.split('_')[0]==postId and '_new' in _]]
    productPosts = list(product(*post_snippets))
    for x, y in productPosts:
        with open(csPath + x, 'r') as f: x_data = f.readlines()
        with open(csPath + y, 'r') as f: y_data = f.readlines()
        x_data = [_.strip() for _ in x_data if _.strip()!="\n" and _.strip()!='']
        y_data = [_.strip() for _ in y_data if _.strip()!="\n" and _.strip()!='']
        x_data = removeComment('\n'.join(x_data))
        y_data = removeComment('\n'.join(y_data))
        if len(x_data) ==0 or len(y_data) ==0:
            continue
        with open(csPath + x, 'w') as f: f.write(x_data)
        with open(csPath + y, 'w') as f: f.write(y_data)
        score = jaccard_similarity(x_data,y_data)
        jaccard_result.append([x, y, score])

    # Diff code snippets in the order of high similarity. (Prerequisite: Similarity scores are higher than the threshold.)
    jaccard_result = sorted(jaccard_result, key =lambda x:float(x[-1]), reverse=True)
    finishedPair = []
    for i in jaccard_result:
        if i[0] in finishedPair:
            continue
        if i[1] in finishedPair:
            continue
        finishedPair.append(i[0])
        finishedPair.append(i[1])
        if float(i[2]) >= float(theta):
            shutil.copyfile(csPath+i[0], pairingcsPath+i[0])
            shutil.copyfile(csPath+i[1], pairingcsPath+i[1])

            diffFileName = diffing(pairingcsPath +i[0], pairingcsPath+i[1])

            if os.path.getsize(diffFileName) < 1:
                os.remove(pairingcsPath+i[0])
                os.remove(pairingcsPath+i[1])
                os.remove(diffFileName)


""" EXECUTE """
if __name__ == "__main__":
	postId = set([_.split('_')[0] for _ in os.listdir(csPath)])
    
	for p in postId:
		Pairing_Codesnippet(p)