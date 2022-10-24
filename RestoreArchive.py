#!/usr/bin/env python

import argparse
import tarfile
import logging
import os
import sys
import pprint

from CreateArchive import verify_tarball
from CreateArchive import decrypt_file as decrypt_archive
from CreateArchive import setup_logging as setup_logging
from CreateArchive import query_yes_no as query
from CreateArchive import get_password as get_password
from CreateArchive import create_filelist_with_checksums
from CreateArchive import md5_checksum


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    usage = "Restore a compressed and encrypted archive of a given folder."
    parser = argparse.ArgumentParser(usage=usage)

    parser.add_argument("--print_cmds_only", action="store_true", dest="print_cmds_only", default=False,
                        help="Only print the commands that would be executed")

    parser.add_argument("--alsologtostderr", action="store_true", dest="alsologtostderr", default=False,
                        help="Also log standard error to console")

    parser.add_argument("-o", "--output_folder", action="store", dest="output_folder",
                        help="Folder to place the restored archive in. If not specified, "
                             "it will be placed in the current folder")

    parser.add_argument("-i", "--input_file", action="store", dest="input_file",
                        help="Archive file to extract")

    parser.add_argument("-f, --file_list", action="store", dest="file_list", default=None,
                        help="File_list generated during the original archiving procedure, used for error checking")

    parser.add_argument("-p", "--plain_text", action="store_true", dest="plain_text", default=False,
                        help="Set this flag if the archive is not encrpyted, which would be unusual")

    args = parser.parse_args()

    # Set up logging
    current_logfile = setup_logging("RestoreArchive", args.alsologtostderr)

    logging.info("*---Python version:---*\n%s\n" % sys.version, args.alsologtostderr)

    # Show help message if no arguments specified
    if not len(sys.argv) > 1:
        print ('This script requires arguments')
        parser.print_help(sys.stderr)
        os.remove(current_logfile)
        sys.exit(2)

    # Verify input archive to extract
    if args.input_file is None:
        logging.critical('No archive specified to extract, please use -i --input_folder')
        os.remove(current_logfile)
        sys.exit(2)

    if os.path.exists(args.input_file):
        if not os.path.isfile(args.input_file):
            print ('Input is a directory or symlink,  this is not valid.')
            os.remove(current_logfile)
            sys.exit(2)
    else:
        print ('Cannot find archive, please specify the full path')
        parser.print_help(sys.stdout)
        os.remove(current_logfile)
        sys.exit(2)

    # Verify output folder
    if args.output_folder is not None:
        if not args.output_folder.translate(None, '-_/').isalnum():
            logging.warning('Folder to place extracted archive \n%s \ncontains characters that are not alphanumeric, '
                            'hypens or dashes.\nWill use the current directory instead.', args.output_folder)
            args.output_folder = os.path.curdir()

        if not os.path.isdir(args.output_folder):
            logging.critical('Output folder %s is not a valid directory', args.output_folder)
            os.remove(current_logfile)
            sys.exit(2)
    # Verify filelist
    if args.file_list is None:
        logging.warning("You are extracting an archive without a filelist, this is not recommended")
    elif not os.path.isfile(args.file_list):
        logging.critical('Specified to filelist %s cannot be found.', args.file_list)
        os.remove(current_logfile)
        sys.exit(2)

    # Verify we won't overwrite anything
    output_file = os.path.join(args.output_folder, os.path.basename(args.input_file.rstrip('.enc')))
    if os.path.exists(output_file):
        logging.critical('Output file %s already exists, will not overwrite', output_file)
        os.remove(current_logfile)
        sys.exit(2)

    output_folder_contents = os.listdir(args.output_folder)
    output_folder_contents = [x for x in output_folder_contents if not ('.App' in x or '.DS_Store' in x)]
    if output_folder_contents:
        logging.warning("****************************\n"
                        "YOU ARE NOT EXTRACTING INTO AN EMPTY FOLDER\n"
                        "This is highly discouraged, especially if you are extracting into a space others use.\n"
                        "****************************\n"
                        "Contents of output folder %s:\n"
                        "%s", args.output_folder, output_folder_contents)

    logging.info('====> These are the parameters this script will use:', args.alsologtostderr)
    logging.info(pprint.pprint(vars(args)), args.alsologtostderr)

    if query("Do you wish to continue?", default="yes") == "no":
        print ("fine, be like that")
        sys.exit(2)
    else:
        print ("Glad everything is satisfactory")

    output_file = os.path.join(args.output_folder, os.path.basename(args.input_file.rstrip('.enc')))

    if not args.plain_text:
        archive_password = get_password(reason='archive restoration', tries=3, min_length=1)

        decrypt_archive(archive_password, args.input_file, output_file)
        logging.info("Archive %s has been decrypted into %s" % (args.input_file, output_file), args.alsologtostderr)
        logging.info("Verifying tarball %s ...." % output_file, args.alsologtostder)
        decrypt_success = verify_tarball(output_file, file_list_checksums=args.file_list, deep_check=True)
        if not decrypt_success:
            logging.critical("Decryption was not successful, tarball verification failed\n"
                             "Are you sure the password is correct?")
            sys.exit(1)

    with tarfile.open(output_file, "r") as basic_tar:
        def is_within_directory(directory, target):
            
            abs_directory = os.path.abspath(directory)
            abs_target = os.path.abspath(target)
        
            prefix = os.path.commonprefix([abs_directory, abs_target])
            
            return prefix == abs_directory
        
        def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
        
            for member in tar.getmembers():
                member_path = os.path.join(path, member.name)
                if not is_within_directory(path, member_path):
                    raise Exception("Attempted Path Traversal in Tar File")
        
            tar.extractall(path, members, numeric_owner=numeric_owner) 
            
        
        safe_extract(basic_tar, args.output_folder)
        extracted_folder = os.path.join(args.output_folder, os.path.commonprefix(basic_tar.getnames()))
        logging.info("Intermediate tarfile %s has been extracted into %s, and will now be checked" %
                   (output_file, extracted_folder), args.alsologtostderr)
        create_filelist_with_checksums(extracted_folder, extracted_folder + '_extracted.filelist', )

    if args.file_list is not None:
        original_hash = md5_checksum(args.file_list)
        new_hash = md5_checksum(extracted_folder + '_extracted.filelist')
        if original_hash == new_hash:
            logging.info("Extraction verified, original and generated filelist are the same", args.alsologtostderr)
        else:
            logging.info("Something may be slightly wrong, generated filelist is different to the original one", args.alsologtostderr)
    else:
        logging.info("New file list generated, but nothing to compare it to. It's probably fine.....", args.alsologtostderr)

    logging.info("Removing intermediate tar file %s" % output_file, args.alsologtostderr)
    os.remove(output_file)
    logging.info("Restoration successful", args.alsologtostderr)


