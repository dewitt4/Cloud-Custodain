import fnmatch
import os
import jmespath
import json


event_change = [
    [('userIdentity', 'accountId'), '101010101111'],
    [('sourceIPAddress',), '192.168.1.2'],
    [('userIdentity', 'accessKeyId'), 'notasecret'],
    [('userIdentity', 'arn'),
     'arn:aws::sts:101010101111:assumed-role/UserRole/userid'],
    [('userIdentity', 'sessionContext', 'sessionIssuer', 'arn'),
     'arn:aws::sts:101010101111:assumed-role/UserRole/userid'],
    [('userIdentity', 'principalId'), 'globalgook:userid'],
    [('userIdentity', 'sessionContext', 'sessionIssuer', 'accountId'),
     '101010101111'],
    [('userIdentity', 'sessionContext', 'sessionIssuer', 'userName'),
     'DeveloperRole'],
    [('userIdentity', 'sessionContext', 'sessionIssuer', 'accountId'),
     '101010101111'],
    [('recipientAccountId',), '101010101111'],
    [('account',), '101010101111'],    
    ]

sentinels = [
    ]


def rewrite_event(content):
    data = json.loads(content)
    modified = False
    for traverse, value in event_change:
        n = data
        for t in traverse[:-1]:
            n = n.get(t, None)
            if n is None:
                break
        
        if n and traverse[-1] in n and n[traverse[-1]] != value:
            modified = True
            n[traverse[-1]] = value
        
    return json.dumps(data, indent=2), modified

            
            

def rewrite(path, event=False):

    content = open(path).read()
    modified = False
    for sentinel, replace in sentinels:
        if sentinel in content:
            modified = True
            content = content.replace(sentinel, replace)

    if event:
        content, mod = rewrite_event(content)
        if mod:
            modified = mod
            
    if modified:
        print "rewriting", path
        with open(path, 'w') as fh:
            fh.write(content)


def main():

    for directory, event in (
            ('tests/data/placebo', False),
            ('tests/data/cwe', True)):
        
        for root, dirs, files in os.walk(directory):
            files = fnmatch.filter(files, "*.json")
            for f in files:
                p = os.path.join(root, f)
                rewrite(p, event)

            
if __name__ == '__main__':
    try:
        main()
    except:
        import traceback, pdb, sys
        traceback.print_exc()
        pdb.post_mortem(sys.exc_info()[-1])
        


