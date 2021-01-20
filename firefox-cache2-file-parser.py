#!/usr/bin/env python3

import argparse
import os
import struct
import datetime
import hashlib
import csv
from urllib.parse import urlparse
import tempfile
import re
import shutil
import gzip
import zlib

argParser = argparse.ArgumentParser(description='Parse Firefox cache2 files in a directory or individually.')
argParser.add_argument('-f', '--file', help='single cache2 file to parse')
argParser.add_argument('-d', '--directory', help='directory with cache2 files to parse')
argParser.add_argument('-s', '--save', action='store_true', help='Save files, mutually exclusive with --print')
argParser.add_argument('-p', '--print', action='store_true', help='Print file content, mutually exclusive with --save')
argParser.add_argument('-c', '--csv', help='CSV output file')
argParser.add_argument('-o', '--output', default=".", help='Save files to this output directory')
argParser.add_argument('-r', '--regex', help='process only files whose origin URL match this regex')
argParser.add_argument('-e', '--exclude', help='do not process files whose origin URL match this regex')
argParser.add_argument('-v', '--verbose', action='store_true', help='be verbose')

args = argParser.parse_args()


chunkSize = 256 * 1024

script_dir = os.path.dirname(__file__)



def GenFilename(url, file):
    parsed = urlparse(url)
    basename = os.path.basename(parsed.path)

    return basename

def is_gzipped(data):
    #with open(filepath, 'rb') as test_f:
    data.seek(0, os.SEEK_SET)
    return data.read(2) == b'\x1f\x8b'



def ParseCacheFile (parseFile):
    args.verbose and print("parsing file: {0}".format(parseFile.name))
    fileSize = os.path.getsize(parseFile.name)
    parseFile.seek(-4, os.SEEK_END)
    metaStart = struct.unpack('>I', parseFile.read(4))[0]
    numHashChunks = metaStart // chunkSize
    if metaStart % chunkSize :
        numHashChunks += 1
    parseFile.seek(metaStart + 4 + numHashChunks * 2, os.SEEK_SET)
    #print parseFile.tell()
    version = struct.unpack('>I', parseFile.read(4))[0]
    #if version > 1 :
        # TODO quit with error
    fetchCount = struct.unpack('>I', parseFile.read(4))[0]
    lastFetchInt = struct.unpack('>I', parseFile.read(4))[0]
    lastModInt = struct.unpack('>I', parseFile.read(4))[0]
    frecency = struct.unpack('>I', parseFile.read(4))[0]
    expireInt = struct.unpack('>I', parseFile.read(4))[0]
    keySize = struct.unpack('>I', parseFile.read(4))[0]
    flags = struct.unpack('>I', parseFile.read(4))[0] if version >= 2 else 0
    key_encoded = parseFile.read(keySize)
    key = key_encoded.decode('utf-8').split(":", 1)[1]
    #print(key)
    key_hash = hashlib.sha1(key_encoded).hexdigest().upper()

    if args.exclude and re.search(args.exclude, key) :
        #print("KO " + key)
        return None

    if args.regex and not re.search(args.regex, key) :
        return None

    #print("OK " + key)
    
    if doCsv :
        csvWriter.writerow((fetchCount,
                            datetime.datetime.fromtimestamp(lastFetchInt),
                            datetime.datetime.fromtimestamp(lastModInt),
                            hex(frecency),
                            datetime.datetime.fromtimestamp(expireInt),
                            flags,
                            key,
                            key_hash))

    print("fileSize : {0} ".format(fileSize))
    args.verbose and print("metaStart : {0} ".format(metaStart))
    args.verbose and print("4 + numHashChunks * 2  =  {0} ".format(4 + numHashChunks * 2))
    args.verbose and print("version: {0}".format(version))
    args.verbose and print("fetchCount: {0}".format(fetchCount))
    print("lastFetch: {0}".format(datetime.datetime.fromtimestamp(lastFetchInt)))
    print("lastMod: {0}".format(datetime.datetime.fromtimestamp(lastModInt)))
    args.verbose and print("frecency: {0}".format(hex(frecency)))
    print("expire: {0}".format(datetime.datetime.fromtimestamp(expireInt)))
    args.verbose and print("keySize: {0}".format(keySize))
    args.verbose and print("flags: {0}".format(flags))
    print("key: {0}".format(key))
    args.verbose and print("key sha1: {0}\n".format(key_hash))
    print("--")

    # Save file in cache
    if args.save :

        parseFile.seek(0, os.SEEK_SET)
        data = parseFile.read(metaStart)
        tmp = None
        with tempfile.NamedTemporaryFile(delete=False) as data_out:
            tmp = data_out.name
            data_out.write(data)

        if is_gzipped(parseFile):
            tmp_uncompressed = None
            with gzip.open(tmp, 'rb') as f:
                with tempfile.NamedTemporaryFile(delete=False) as data_out_uncompressed:
                    tmp_uncompressed = data_out_uncompressed.name
                    file_content = f.read()
                    data_out_uncompressed.write(file_content)
            os.remove(tmp)
            tmp = tmp_uncompressed

        name = GenFilename(key, tmp)
        shutil.move(tmp, args.output + "/" + name)

    elif args.print:
        parseFile.seek(0, os.SEEK_SET)
        data = parseFile.read(metaStart)
        
        if is_gzipped(parseFile):
            data = zlib.decompress(data, zlib.MAX_WBITS|16)
            
        print(data.decode("UTF-8"))
        

if args.directory or args.file :
    doCsv = False
    if args.csv :
        doCsv = True
        csvFile = open(args.csv, 'w')
        csvWriter = csv.writer(csvFile, delimiter=',', quoting=csv.QUOTE_NONNUMERIC)
        csvWriter.writerow(('Fetch Count', 'Last Fetch', 'Last Modified', 'Frecency', 'Expiration', 'Flags', 'URL', 'Key Hash'))

    procPath = fileList = None
    if args.directory:
        procPath = args.directory
        fileList = os.listdir(procPath)
    elif args.file:
        procPath = ""
        fileList = [ args.file ]

    for filePath in fileList :
        file = open(procPath + '/' + filePath, 'rb')
        ParseCacheFile(file)
    if doCsv :
        print('Data written to CSV file: {0}'.format(csvFile.name))
        csvFile.close()
else :
    argParser.print_help()
