#!/usr/bin/python

import sys, getopt
import os
import mimetypes
import hashlib
import dbm.ndbm
import subprocess
import re
import configparser
import tempfile
import shutil

def hash_bytestr_iter(bytesiter, hasher, ashexstr=False):
    for block in bytesiter:
        hasher.update(block)
    return hasher.hexdigest() if ashexstr else hasher.digest()

def file_as_blockiter(afile, blocksize=65536):
    with afile:
        block = afile.read(blocksize)
        while len(block) > 0:
            yield block
            block = afile.read(blocksize)

def list_of_file(path):
    files = []
    # r=root, d=directories, f = files
    for r, d, f in os.walk(path):
        for file in f:
            #print(file)
            filepath=os.path.join(r, file)
            #mime = mimetypes.guess_type(filepath)
            if os.access(filepath, os.R_OK) and os.path.isfile(filepath):
                files.append(filepath)
    return files

def list_of_exec(path):
    files = []
    # r=root, d=directories, f = files
    for r, d, f in os.walk(path):
        for file in f:
            filepath=os.path.join(r, file)
            #mime = mimetypes.guess_type(filepath)
            bypass = False
            for folder in ['/proc','/sys','/dev']:
                if filepath.startswith(folder):
                    bypass = True
            if not bypass:
                if os.access(filepath, os.X_OK) and os.path.isfile(filepath):
                    print(filepath)
                    ret = execute("readlink -f \"%s\""%(filepath))
                    print(ret)
                    files.append(ret.rstrip())

    return files

def get_md5(file_):
    md5res = hash_bytestr_iter(file_as_blockiter(open(file_, 'rb')), hashlib.md5())
    return md5res

def execute(cmd, display=False):
    print('Executing',cmd)
    import subprocess
    #result = subprocess.run(cmd.split(' '), stdout=subprocess.PIPE)
    cmd = ['bash','-c',cmd]

    stdout=[]
    popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
    for stdout_line in iter(popen.stdout.readline, ""):
        if display:
            print(stdout_line)
        stdout.append(stdout_line)
    popen.stdout.close()
    return_code = popen.wait()
    if return_code:
        return None
    else:
        return ''.join(stdout)

def ByteToHex( byteStr ):
    """
    Convert a byte string to it's hex string representation e.g. for output.
    """
    #return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()
    return ''.join( [ "%02X"%x for x in byteStr ] ).strip()

path = '/usr/local/cuda'
class binary_checker:
    def __init__(self, args):
        self.config = {}
        self.config['Files']={}
        self.config['Exec']={}
        self.config['Libs']={}
        self.args = args

        db = dbm.ndbm.open('cache', 'c')
        self.db = db

        release = execute("lsb_release -c -s")
        if not release:
            os.exit(-1)
        self.release = release.rstrip()

    def generate_key(self, execfile, dictFile):
        #print(execfile, dictFile)
        key=dictFile['package']+':'+dictFile['version']+':'+dictFile['release']+':'+dictFile['arch']+':'+execfile
        return key

    def add_error(self, file, cause):
        self.errors.append((file, cause))
        print("ERROR", file, cause)
        os.exit(-1)


    def validate_config(self):
        self.errors = []
        for execfile in self.config['Exec']:
            dictFile = self.config['Exec'][execfile]
            print("CHECKING", execfile,dictFile ,"...")
            if 'version' in dictFile:
                key=self.generate_key(execfile,dictFile)
                need_validation = True

                if key in self.db:
                    need_validation = False

                if need_validation:
                    self.validate_file(execfile,dictFile)
                    # second pass after package reading
                    if key not in self.db:
                        self.add_error(execfile, "File not found in package")
                        continue

                if self.db[key].decode('utf-8') != dictFile['hash']:
                    self.add_error(execfile, "File not match md5 (%s!=%s)"%(dictFile['hash'],self.db[key]))
                    continue

                print("GOOD")


    def insert_base(self, execfile, dictfile):
        key=self.generate_key(execfile,dictfile)
        print("INSERTING",execfile,dictfile)
        #if key not in self.db:
        #    self.db[key] = []
        self.db[key] = dictfile['hash']

    def validate_file(self, execfile, dictfile):
        validate = False
        #print(dictfile)

        tmppath = tempfile.mkdtemp()
        origpath = os.getcwd()
        os.chdir(tmppath)
        #print(tmppath)
        try:
            resapt = execute("apt download %s=%s"%(dictfile['package'],dictfile['version']))
            #print("apt",resapt)
            #print(execute("ls -la"))
            if resapt != None:
                version = dictfile['version']
                version = version.replace(':','%3a')
                debfile = "%s_%s_%s.deb"%(dictfile['package'],version,dictfile['arch'])
                resmd5 = execute("dpkg -I ./%s md5sums"%(debfile))
                #print("apt",resmd5)
                if resmd5 != None:
                    listmd5 = resmd5.split('\n')
                    for md5 in listmd5:
                        filetmplist = md5.split()
                        md5tmp = filetmplist[0].upper()
                        filetmp = '/'+filetmplist[1]
                        #print(filetmp,md5tmp,execfile)
                        if filetmp == execfile:
                            dictNew = {}
                            dictNew['version'] = dictfile['version']
                            dictNew['package'] = dictfile['package']
                            dictNew['arch'] = dictfile['arch']
                            dictNew['release'] = dictfile['release']
                            dictNew['file'] = execfile
                            dictNew['hash'] = md5tmp
                            self.insert_base(execfile,dictfile)
                            break

            shutil.rmtree(tmppath)
        except Exception as e:
            print(e)
            print("ERROR during validation")
            os.exit(-1)
        finally:
            print("removing %s"%(tmppath))
            os.chdir(origpath)
            #  dpkg -I kbd_2.0.4-2ubuntu1_amd64.deb md5sums

        # Todo check signature
    def generate_dict(self, file):
        dict = {}
        pckg = None
        version = None
        arch = None

        retfile = execute("readlink -f \"%s\""%(file)).rstrip()
        md5tmp = b'00000000'
        if not retfile.startswith("/proc"):
            md5tmp = get_md5(retfile)

            #print(file, ByteToHex(md5tmp))
            ec = execute("dpkg -S %s"%retfile)
            if ec:
                ecs = ec
                #print(ecs)
                m = re.search("^(?P<package>[a-zA-Z0-9_:\.+-]*):\s",ecs,re.MULTILINE)
                if m:
                    pckg = m.group('package')
                    #print(pckg)
                    ec =execute("dpkg -s %s"%pckg)
                    if ec:
                        ecv = ec
                        #print(ecv)
                        m = re.search("^Version:\s(?P<version>[a-zA-Z0-9._:~+-]*)$",ecv,re.MULTILINE)
                        if m:
                            version = m.group('version')
                            #print(version)
                        m = re.search("^Architecture:\s(?P<arch>[a-zA-Z0-9._:-]*)$",ecv,re.MULTILINE)
                        if m:
                            arch = m.group('arch')
                            #print(arch)

        dict_ = {'hash':ByteToHex(md5tmp), 'package':pckg, 'version':version, 'arch':arch, 'release':self.release, 'readlink':retfile}
        print(dict_)
        return dict_
    def check_file(self, folder):
        listf = list_of_file(folder)
        file_cnt = 0
        for file in listf:
            print(file)
            self.config['Files'][str(file)] = self.generate_dict(file)
            file_cnt += 1
            if self.args['limit'] and file_cnt > self.args['limit']:
                break

    def check_exec(self, folder):
        listf = list_of_exec(folder)
        file_cnt = 0
        for file in listf:
            self.config['Exec'][str(file)]=self.generate_dict(file)
            file_cnt += 1
            if self.args['limit'] and file_cnt > self.args['limit']:
                break

    def check_ld(self):
        ld_list = []

        res = execute("ldconfig -p")
        m = re.findall("/[0-9a-zA-Z+.//_-]*",str(res))
        file_cnt = 0
        ld_list = m
        for file in ld_list:
            ret = execute("readlink -f \"%s\""%(file)).rstrip()
            self.config['Libs'][str(file)] = self.generate_dict(ret)

            file_cnt += 1
            if self.args['limit'] and file_cnt > self.args['limit']:
                break

    def write_config_file(self):
        statefile = self.args['statefile']
        print("Writing to %s"%(statefile))
        import json
        with open(statefile, 'w') as fp:
            json.dump(self.config, fp, sort_keys=True, indent=4)

    def read_config_file(self):
        statefile = self.args['statefile']
        print("Reading from %s"%(statefile))
        import json
        with open(statefile, 'r') as fp:
            self.config = json.load(fp)

def usage():
    print('test.py -i <inputfile>')
    sys.exit()


def main(argv):
   args = {}
   args['inputfile'] = ''
   args['dbfile'] = ''
   args['statefile'] = '/tmp/system-footprint.json'
   args['check_exe'] = False
   args['validate_db'] = False
   args['limit'] = None
   try:
      opts, args_ = getopt.getopt(argv,"ha:i:b:s:gvl",["ifile=","statefile=","dbfile=","generate-state","validate-state","limit"])
   except getopt.GetoptError:
      usage()
   for opt, arg in opts:
      if opt == '-h':
         usage()
      elif opt in ("-i", "--ifile"):
         args['inputfile'] = arg
      elif opt in ("-s", "--statefile"):
         args['statefile'] = arg
      elif opt in ("-b", "--dbfile"):
         args['dbfile'] = arg
      elif opt in ("-g", "--generate-state"):
         args['check_exe'] = True
      elif opt in ("-v", "--validate-state"):
         args['validate_db'] = True
      elif opt in ("-l", "--limit-state"):
         args['limit'] = 10

   print("ARGS:",args)

   a=binary_checker(args)
   if args['check_exe']:
       if not args['statefile']:
           usage()
       a.check_file('/etc')
       a.check_file('/boot')
       a.check_exec('/bin')
       a.check_exec('/usr/bin')
       a.check_ld()
       a.write_config_file()
       sys.exit(0)

   elif args['validate_db']:
       if not args['statefile']:
           usage()
       else:
           a=binary_checker(args)
           a.read_config_file()
           a.validate_config()
           sys.exit(0)
   else:
        usage()

if __name__ == "__main__":
   main(sys.argv[1:])
