import argparse
import os
import struct
import datetime
import hashlib
import csv

argParser = argparse.ArgumentParser(description='Parse Firefox cache2 files in a directory or individually.')
argParser.add_argument('-f', '--file', help='single cache2 file to parse')
argParser.add_argument('-d', '--directory', help='directory with cache2 files to parse')
argParser.add_argument('-s', '--save', help='Save files')
argParser.add_argument('-o', '--output', help='CSV output file')
args = argParser.parse_args()


chunkSize = 256 * 1024

script_dir = os.path.dirname(__file__)

def ParseCacheFile (parseFile):
    print "parsing file: {0}".format(parseFile.name)
    fileSize = os.path.getsize(parseFile.name)
    parseFile.seek(-4, os.SEEK_END)
    #print parseFile.tell()
    #print filesize
    print "fileSize : {0} ".format(fileSize)
    metaStart = struct.unpack('>I', parseFile.read(4))[0]
    #print metaStart
    print "metaStart : {0} ".format(metaStart)
    numHashChunks = metaStart / chunkSize
    if metaStart % chunkSize :
        numHashChunks += 1
    #print 4 + numHashChunks * 2
    print "4 + numHashChunks * 2  =  {0} ".format(4 + numHashChunks * 2)
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
    key = parseFile.read(keySize)
    key_hash = hashlib.sha1(key).hexdigest().upper()

    if doCsv :
        csvWriter.writerow((fetchCount,
                            datetime.datetime.fromtimestamp(lastFetchInt),
                            datetime.datetime.fromtimestamp(lastModInt),
                            hex(frecency),
                            datetime.datetime.fromtimestamp(expireInt),
                            flags,
                            key,
                            key_hash))

    print "version: {0}".format(version)
    print "fetchCount: {0}".format(fetchCount)
    print "lastFetch: {0}".format(datetime.datetime.fromtimestamp(lastFetchInt))
    print "lastMod: {0}".format(datetime.datetime.fromtimestamp(lastModInt))
    print "frecency: {0}".format(hex(frecency))
    print "expire: {0}".format(datetime.datetime.fromtimestamp(expireInt))
    print "keySize: {0}".format(keySize)
    print "flags: {0}".format(flags)
    print "key: {0}".format(key)
    print "key sha1: {0}\n".format(key_hash)

    # Save file in cache
    if args.save :
        parseFile.seek(0, os.SEEK_SET)
        data = parseFile.read(metaStart)
        with open("/tmp/out", "wb") as data_out:
            data_out.write(data)

#ParseCacheFile(testFile)
#procPath = script_dir + '/' + testDir
if args.directory or args.file :
    doCsv = False
    if args.output :
        doCsv = True
        csvFile = open(args.output, 'w')
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
        print 'Data written to CSV file: {0}'.format(csvFile.name)
        csvFile.close()
else :
    argParser.print_help()
