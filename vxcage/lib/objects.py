# -*- coding: utf-8 -*-

import ConfigParser
import StringIO
import binascii
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib
import urllib2

import importlib

# PIP imports

try:
    import pydeep
    HAVE_SSDEEP = True
except MemoryError:
    logging.exception("Out of memory")
    sys.exit("Out of memory error")
except ImportError:
    HAVE_SSDEEP = False # Should change this to 'bomb on missing' in configuration file

try:
    import magic
except MemoryError:
    logging.exception("Out of memory")
    sys.exit("Out of memory error")
except ImportError:
    sys.exit("ERROR: python-magic library is missing")

try:
    import exiftool
except MemoryError:
    logging.exception("Out of memory")
    sys.exit("Out of memory error")
except ImportError:
    sys.exit("ERROR: EXIFTool library is missing")

try:
    import virustotal
except MemoryError:
    logging.exception("Out of memory")
    sys.exit("Out of memory error")
except ImportError:
    sys.exit("ERROR: Virustotal library is missing")


#-----------------------------------------------------------------------------
# Code
#-----------------------------------------------------------------------------

logging.basicConfig(
    format="%(levelname) -10s %(asctime)s %(message)s",
    level=logging.DEBUG
)

FILE_CHUNK_SIZE = 16 * 1024

class Dictionary(dict):
    def __getattr__(self, key):
        return self.get(key, None)

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

class File:
    def __init__(self, file_path=None, file_data=None, tags=None):
        self.file_path = file_path
        self.filenames = []
        self.tags = []
        
        if tags:
            self.tags.extend(tags.split(" "))

        if file_path:
            self.file_data = open(self.file_path, "rb").read()
        else:
            self.file_data = file_data

        try:
            if "PE" in self.get_type():
                self.pe = pefile.PE(data=self.file_data)
            else:
                self.pe = None
        except MemoryError:
            logging.exception("Out of memory")
            sys.exit("Out of memory error")
        except Exception:
            self.pe = None
            
        self.pathname = os.path.abspath(os.path.dirname(sys.argv[0]))

    def get_filenames(self):
        ''' return all known filenames for the sample '''
        return self.filenames

    def get_filename(self):
        ''' return the first known filename for the sample '''
        logging.debug("Number of filenames: {0}".format(len(self.filenames)))
        return self.filenames[0]
    
    def add_filename(self, file_name=None):
        ''' add file_name to the list of known filenames for the sample '''
        if file_name:
            self.filenames.append(file_name)
        self.filenames = list(set(self.filenames))  # Make sure we don't have duplicate filenames

    def get_tags(self):
        ''' return all tags for the sample '''
        return self.tags
    
    def add_tag(self, tag=None):
        ''' add a tag to the sample '''
        if tag:
            self.tags.append(tag)
        self.tags = list(set(self.tags))  # Make sure we don't have duplicate tags

    def del_tag(self, tag=None):
        ''' delete a tag from the sample '''
        while tag in self.tags:
            self.tags.remove(tag)

    def get_name(self):
        logging.error("Depreciated function get_name() called, re-routed to get_filename()")
        return self.get_filename()

    def get_data(self):
        return self.file_data

    def get_chunks(self):
        """Read file contents in chunks (generator)."""
        fd = StringIO.StringIO(self.file_data)
        while True:
            chunk = fd.read(FILE_CHUNK_SIZE)
            if not chunk: break
            yield chunk
        fd.close()

    def get_size(self):
        return len(self.file_data)

    def get_crc32(self):
        res = ''
        crc = binascii.crc32(self.file_data)
        for i in range(4):
            t = crc & 0xFF
            crc >>= 8
            res = '%02X%s' % (t, res)
        return res

    def get_md5(self):
        return hashlib.md5(self.file_data).hexdigest()

    def get_sha1(self):
        return hashlib.sha1(self.file_data).hexdigest()

    def get_sha256(self):
        return hashlib.sha256(self.file_data).hexdigest()

    def get_sha512(self):
        return hashlib.sha512(self.file_data).hexdigest()

    def get_ssdeep(self):
        if not HAVE_SSDEEP:
            return None
        try:
            return pydeep.hash_buf(self.file_data)
        except MemoryError:
            logging.exception("Out of memory")
            sys.exit("Out of memory error")
        except Exception:
            return None

    def get_type(self):
        try:
            ''' Try to get file magic information, method 1 '''
            ms = magic.open(magic.MAGIC_NONE)
            ms.load()
            file_type = ms.buffer(self.file_data)
        except MemoryError:
            logging.exception("Out of memory")
            sys.exit("Out of memory error")
        except:
            try:
                ''' Try to get file magic information, method 2 '''
                file_type = magic.from_buffer(self.file_data)
            except MemoryError:
                logging.exception("Out of memory")
                sys.exit("Out of memory error")
            except:
                try:
                    ''' Try to get file magic information, method 3 '''
                    ''' Run the 'file' command, passing the file data via STDIN '''
                    file_process = subprocess.Popen(['file', '-b', '-'], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
                    file_process.stdin.write(self.file_data)
                    file_type = file_process.stdout.read().strip()
                except MemoryError:
                    sys.exit("Out of memory error")
                except:
                    return None

        return file_type

    def get_exif(self):
        metadata = None
        uselessexifkey = [u'SourceFile', u'File:FilePermissions', u'File:Directory', u'ExifTool:ExifToolVersion',
                          u'File:FileModifyDate', u'File:FileName', u'File:FileSize']
        '''
        with exiftool.ExifTool() as et:
            tfile = tempfile.NamedTemporaryFile(mode='w+b')
            try:
                tfile.write(self.file_data)
                tfile.flush()

                logging.debug('temp file name:', tfile.name)

                metadata = et.get_metadata(tfile.name)
            finally:     
                tfile.close()            
            
            for key in uselessexifkey:
                del metadata[key]
        '''
        return json.dumps(metadata)

    def get_peheaders(self):
        metadata = {}
        if not self.pe:
            return json.loads('{"pe" : 0}')
        else:
            pe = self.pe

        if hasattr(pe, 'VS_VERSIONINFO'):
            if hasattr(pe, 'FileInfo'):
                for entry in pe.FileInfo:
                    if hasattr(entry, 'StringTable'):
                        for st_entry in entry.StringTable:
                            for str_entry in st_entry.entries.items():
                                metadata[str_entry[0]] = str_entry[1]
                    elif hasattr(entry, 'Var'):
                        for var_entry in entry.Var:
                            if hasattr(var_entry, 'entry'):
                                metadata[var_entry.entry.keys()[0]] = var_entry.entry.values()[0]
        
            if "Translation" in metadata and " " in metadata["Translation"]:
                metadata["langID"], metadata["charsetID"] = metadata["Translation"].split(" ")
        else:
            print("PE file has no VS_VERSIONINFO attribute")

        try:
            metadata['TimeDateStamp'] = {}
            metadata['TimeDateStamp']["raw"] = pe.FILE_HEADER.TimeDateStamp
            try:
                metadata['TimeDateStamp']["gmtime"] = time.strftime("%a %d %b %Y %H:%M:%S (GMT+0000)", time.gmtime((pe.FILE_HEADER.TimeDateStamp)))
                metadata['TimeDateStamp']["iso8601"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime((pe.FILE_HEADER.TimeDateStamp)))
            except Exception:
                logging.exception("Failed to interpret TimeStampValue {0}".format(pe.FILE_HEADER.TimeDateStamp))
        except Exception:
            logging.exception("Failed to get TimeDateStamp")

        return json.dumps(metadata)

    def get_pesections(self):
        metadata = {}
        if not self.pe:
            return json.loads('{"pe" : 0}')
        else:
            pe = self.pe
        for section in pe.sections:
            sectionName = re.sub(r'[^A-Za-z0-9]', '', section.Name)  # Remove ALL non alpha-numeric characters
            metadata[sectionName] = {}
            metadata[sectionName]['size'] = section.SizeOfRawData
            metadata[sectionName]['md5'] = section.get_hash_md5()
            metadata[sectionName]['sha1'] = section.get_hash_sha1()
            metadata[sectionName]['ssdeep'] = section.get_hash_ssdeep()
            metadata[sectionName]['sha256'] = section.get_hash_sha256()
            metadata[sectionName]['sha512'] = section.get_hash_sha512()

        return json.dumps(metadata)

    def get_imphash(self):
        if not self.pe:
            return
        else:
            pe = self.pe
        return pe.get_imphash()

    def get_pefunctions(self):
        metadata = {}
        if not self.pe:
            return json.loads('{"pe" : 0}')
        else:
            pe = self.pe
        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dllName = entry.dll.lower().replace(".dll", "")
                metadata[dllName] = []
                for imp in entry.imports:
                    metadata[dllName].append(imp.name)
        except MemoryError:
            logging.exception("Out of memory")
            sys.exit("Out of memory error")
        except Exception:
            return json.loads('{"pe" : -1}')
        return json.dumps(metadata)

    def get_peexports(self):
        metadata = []
        if not self.pe:
            return json.loads('{"pe" : 0}')
        else:
            pe = self.pe
        try:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                metadata.append(exp.name)
        except MemoryError:
            logging.exception("Out of memory")
            sys.exit("Out of memory error")
        except Exception:
            return json.loads('{"pe" : -1}')

        return metadata
    
    def get_peid(self):
        ''' get PEiD compiler/packer identification '''
        if not self.pe:
            return None
        else:
            pe = self.pe
        try:
            logging.debug("searching for peid file: " + self.pathname + '/../ext/data/userdb.txt')
            signatures = peutils.SignatureDatabase(self.pathname + '/../ext/data/userdb.txt')
            matches = signatures.match_all(pe, ep_only=True)
            logging.debug("Matched PEiD signature(s): {0}".format(' '.join(matches[0])))
            return matches[0][0]
        except MemoryError:
            logging.exception("Out of memory")
            sys.exit("Out of memory error")
        except Exception:
            return None
    
    def get_pdfid(self):
        metadata = None
        try:
            options = {}
            options["all"] = True
            options["extra"] = True
            options["disarm"] = False
            options["force"] = False

            tfile = tempfile.NamedTemporaryFile(mode='w+b')
            tfile.write(self.file_data)
            tfile.flush()
            metadata = json.loads(PDFiD2JSON(PDFiD(self.file_path, options['all'], options['extra'], options['disarm'], options['force'])))
            tfile.close()
        except MemoryError:
            logging.exception("Out of memory")
            sys.exit("Out of memory error")
        except Exception:
                return json.loads('{"pdfid" : -1}')
        
        return metadata

    def get_virustotal(self):
        ''' Returns VirusTotal report in JSON format '''
        sha256 = self.get_sha256()
        try:
            apikey = Config().virustotal.api_key
        except Exception as e:
                return json.loads('{"virustotal" : -1}')
        try:
            v = virustotal.VirusTotal(apikey)
            VTjson = v.get_raw(sha256)
            return VTjson
        except MemoryError:
            sys.exit("Out of memory error")
        except Exception:
                return json.loads('{"virustotal" : -1}')

class Config:
    def __init__(self, cfg = None):
        
        try:
            logging.debug("Search for configs in: [" + ",".join(cfg) + "]")
            for fname in cfg:
                logging.debug(os.path.abspath(fname) + " Found: " + str(os.path.isfile(fname)))

            config = ConfigParser.ConfigParser()
            
            config.read(cfg)

        except Exception:
            logging.exception("Missing Configuration files.")
            sys.exit("Missing Configuration files.")


        for section in config.sections():
            setattr(self, section, Dictionary())
            for name, raw_value in config.items(section):
                try:
                    value = config.getboolean(section, name)
                except MemoryError:
                    logging.exception("Out of memory")
                    sys.exit("Out of memory error")
                except ValueError:
                    try:
                        value = config.getint(section, name)
                    except MemoryError:
                        logging.exception("Out of memory")
                        sys.exit("Out of memory error")
                    except ValueError:
                        value = config.get(section, name)

                setattr(getattr(self, section), name, value)

        logging.debug( "Using Database String: " + self.api.database)

    def get(self, section):
        try:
            return getattr(self, section)
        except MemoryError:
            logging.exception("Out of memory")
            sys.exit("Out of memory error")
        except AttributeError as e:
            return None
