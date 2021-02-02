#!/usr/bin/env python2

import argparse
import atexit
import bz2
import errno
import datetime
import fnmatch
import getpass
import grp
import gzip
import hashlib
import tarfile
import logging
import math
import os
import pprint
import random
import shutil
import smtplib
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import pwd

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

# Requires pip install pycryptodomex
from Cryptodome.Cipher import AES

# Requires pip install psycopg2-binary
import psycopg2
from psycopg2 import sql


# -----------------------------------------------------------------------------
def setup_logging(
            script_identifier, alsologtostderr=False, logging_dir="/tmp"):
    """Format log messages, send them to console, return log file path.

        Returns the log file it created.
        The log file always includes a date-time stamp

        script_identifier:
            A string used to identify the program generating the file

        alsologtostderr:
            Sets if we should print log.info messages to console

        logging_dir:
            Where the log file will be placed. Defaults to /tmp.
    """
    if not script_identifier:
        logging.warning("===> Cannot set up logging, "
                        "script_identifier not specified")
        return
    # Open logfile.
    start_time_str = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S_%f")
    log_file_name = "%s/%s-%s.log" % (logging_dir.rstrip(os.sep),
                                      script_identifier, start_time_str)
    message_format = "%(asctime)-15s %(levelname)-8s %(message)s"
    logging.basicConfig(filename=log_file_name,
                        level=logging.DEBUG, format=message_format)
    print ("===> Running with logfile: %s" % log_file_name)

    # optionally log to stderr
    console = logging.StreamHandler()
    if alsologtostderr:
        console.setLevel(logging.INFO)
    else:
        console.setLevel(logging.WARNING)

    # set a format which is simpler for console use
    formatter = logging.Formatter("%(name)-12s: %(levelname)-8s %(message)s")
    # tell the handler to use this format
    console.setFormatter(formatter)
    # add the handler to the root logger
    logging.getLogger("").addHandler(console)
    return log_file_name


# -----------------------------------------------------------------------------
# Retrieved from: http://code.activestate.com/recipes/577058/
# by Jonathan Boeuf on 2018-03-06
def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.

    question:
        A string that is presented to the user.

    default:
        The presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is one of "yes" or "no".
    """
    valid = {"yes": "yes", "y": "yes", "ye": "yes", "no": "no", "n": "no"}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while 1:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == "":
            return default
        elif choice in valid.keys():
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


# -----------------------------------------------------------------------------
def get_password(reason, tries=3, min_length=12):
    """Asks user for password on the console, returns it as a string.

       Asks for password with minimum length and asks user to confirm,
       so user can be sure what they typed.
       If user ends entered string with esc character ( \x1b ),
       it aborts that password entry.
       Gives the user a number of tries to consistently enter a good
       password.
       Does not print password to the console as it is entered.

       Inputs
        reason:
            What the password is for, to inform the user.
            Particularly for entry of multiple passwords.

        tries:
            How many times the user can enter a bad password,
            or fail to verify a password.

        min_length:
            A proxy of password strength.
        """
    while tries > 0:
        print ("User may abort current password entry by pressing "
               "esc and enter")
        password = getpass.getpass("Please enter a password for " + reason
                                   + "(minimum length %s): " % min_length)

        if password.endswith("\x1b"):
            print ("User aborted password entry")
            continue
        elif len(password) < min_length:
            print ("Entered password is less than minimum length %s, "
                   "try a different longer password" % min_length)
            continue
        k = 2
        password_verify = ""
        while k > 0:
            password_verify = getpass.getpass("Please confirm password: ")
            if password_verify.endswith("\x1b"):
                print ("User aborted password verification, "
                       "user may try %s times more" % k)
                k -= 1
                continue
            else:
                break

        if password == password_verify:
            print ("Password verified")
            return password
        else:
            tries -= 1
            print ("User inputs not the same, you have %s tries left" % tries)

    print ("You have run out of attempts\nNo valid password entered")
    return ""


# -----------------------------------------------------------------------------
# Retrieved from: "http://code.activestate.com/recipes/499305-locating-
# files-throughout-a-directory-tree/"
def locate(file_pattern, exclude_dirs, root=os.curdir):
    """Locate all files matching supplied filename file_pattern in and
    below supplied root directory.
    """

    for paths, dirs, files in os.walk(os.path.abspath(root), topdown=True):

        new_dirs = []
        for d in dirs:
            full_path = os.path.abspath(os.path.join(paths, d))
            valid_directory = True
            for ex_dir in exclude_dirs:
                if os.path.abspath(ex_dir) == full_path:
                    valid_directory = False
                    break
            if valid_directory:
                new_dirs.append(d)

        dirs[:] = [d for d in new_dirs]

        for filename in fnmatch.filter(files, file_pattern):
            yield os.path.join(paths, filename)


# -----------------------------------------------------------------------------
# Modified version of locate() that works for directories (only).
def locate_dirs(dir_name_pattern, exclude_dirs, root=os.curdir):
    """Locate all directories matching supplied directory name
    file_pattern in and below supplied root directory.
    """

    for paths, dirs, files in os.walk(os.path.abspath(root), topdown=True):

        new_dirs = []
        for d in dirs:
            full_path = os.path.abspath(os.path.join(paths, d))
            valid_directory = True
            for ex_dir in exclude_dirs:
                if os.path.abspath(ex_dir) == full_path:
                    valid_directory = False
                    break
            if valid_directory:
                new_dirs.append(d)

        for dir_name in fnmatch.filter(dirs, dir_name_pattern):
            yield os.path.join(paths, dir_name)

        dirs[:] = [d for d in new_dirs]


# -----------------------------------------------------------------------------
def clean_folder(messy_folder, read_only=True):
    """ Removes apple hidden files from folder.

        Recursively finds and deletes .DStore files  and .AppleDouble
        directories in the input folder.
        Can also change the file permissions to prevent them being
        recreated by accident.

        messy_folder:
            Folder to do this operation on.

        read_only:
            Change the folder to read only once it has been cleaned.

        """
    current_permissions = oct(os.stat(messy_folder)[stat.ST_MODE])[-3:]

    subprocess.call(["chmod", "-R", "750", messy_folder])

    apple_double = locate_dirs(".AppleDouble", "", messy_folder)

    for folder in apple_double:
        logging.info("Found %s", folder)
        shutil.rmtree(folder)
    logging.info(".AppleDouble folders removed")

    ds_store = locate(".DS_Store", "", messy_folder)

    for ds_file in ds_store:
        logging.info("Found %s", ds_file)
        os.remove(ds_file)
    logging.info(".DS_Store files removed")

    if read_only:
        subprocess.call(["chmod", "-R", "550", messy_folder])
    else:
        subprocess.call(["chmod", "-R", current_permissions, messy_folder])


# -----------------------------------------------------------------------------
# Retrieved from: "https://www.joelverhagen.com/blog/
# 2011/02/md5-hash-of-file-in-python/"
# By Jonathan Boeuf on 2018-03-17
def md5_checksum(input_file):
    """Returns md5 checksum of given file.

        Accepts file paths or file handles.
        Returns empty string if error encountered.
        """
    close_file = False
    fh = "Empty file handle"
    try:
        if isinstance(input_file, basestring):
            if (os.path.exists(input_file)
                    and not os.path.isdir(os.path.abspath(input_file))):
                fh = open(input_file, "rb")
                close_file = True
                logging.info("File %s for checksum is valid.", input_file)
            else:
                logging.warning(
                    "File name provided for checksum %s is invalid, "
                    "will not process", input_file)
                return ""
        else:
            fh = input_file

        m = hashlib.md5()
        while True:
            data = fh.read(8192)
            if not data:
                break
            m.update(data)

        return m.hexdigest()

    except IOError as io:
        logging.error(
            "I/O error with file provided, will ignore.\n%s", io)
        return ""

    except AttributeError as at:
        logging.error(
            "Attribute error with file provided, will ignore.\n%s", at)

    except Exception as ex:
        logging.error(
            "Unknown Error occurred with file, will ignore.\n%s", ex)

    finally:
        if close_file:
            fh.close()


# -----------------------------------------------------------------------------
def create_filelist_with_checksums(
        top_folder, file_list_file, delimiter="=",
        checksum_file=True, empty_folder_string="null"):
    """Create relative filelist, potentially with md5 checksums.

    top_folder:
            Folder to look in to get all the files.

    file_list_file:
            The output file that will contain the filelist plus checksums.

    delimiter:
            The symbol that will separate the file path from the checksum.

    checksum_file:
            Will checksums be included.

    """
    logging.info("Creating filelist with checksums %s", file_list_file)
    output_file_list = open(file_list_file, "w")
    for file_to_check in locate("*", "", top_folder):
        logging.info("Found file: %s to add to filelist", file_to_check)
        try:
            os.stat(file_to_check)
        except OSError as er:
            if er.errno == errno.ENOENT:
                logging.warning(
                    "File %s is a broken symlink, will not include in archive",
                    file_to_check)
                continue
            else:
                logging.error(
                    "Something is wrong with file %s, raised OSError:\n%s",
                    file_to_check, er)
                raise er
        filelist_line = os.path.relpath(
            file_to_check,
            os.path.dirname(top_folder))

        if checksum_file:
            logging.info("Generating checksum")
            md5_hash = md5_checksum(file_to_check)
            output_file_list.write(filelist_line
                                   + delimiter
                                   + md5_hash
                                   + "\n", )
        else:
            output_file_list.write(filelist_line, )
        logging.info("File %s added to filelist", file_to_check)

    for folder_to_check in locate_dirs("*", "", top_folder):
        filelist_string = os.path.relpath(
            folder_to_check,
            os.path.dirname(top_folder))

        if not os.listdir(folder_to_check):
            output_file_list.write(
                filelist_string
                + delimiter
                + empty_folder_string
                + "\n", )
            logging.info(
                "Found empty folder %s, will add to filelist",
                folder_to_check)

    output_file_list.close()


# -----------------------------------------------------------------------------
# Retrieved from: https://eli.thegreenplace.net/
# 2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
# By Jonathan Boeuf on 2018-04-04
def encrypt_file(
        password, in_filename, out_filename=None, chunk_size=64 * 1024):
    """ Encrypts a file using AES (CBC mode) with the
        given password.

        password:
            String used to generate the 32 byte key for
            encryption

        in_filename:
            Name of the input file

        out_filename:
            If None, "<in_filename>.enc" will be used.

        chunk_size:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunk_size must be divisible by 16.
    """
    if not out_filename:
        out_filename = in_filename + ".enc"

    iv = "".join(chr(random.randint(0, 0xFF)) for i in range(16))
    #  The encryption 32 byte key is the sha256 hash of the password
    key = hashlib.sha256(password).digest()

    encryptor = AES.new(key, AES.MODE_CBC, iv)
    file_size = os.path.getsize(in_filename)

    with open(in_filename, "rb") as infile:
        with open(out_filename, "wb") as outfile:
            outfile.write(struct.pack("<Q", file_size))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += " " * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))


# -----------------------------------------------------------------------------
# Retrieved from: https://eli.thegreenplace.net/
# 2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
# By Jonathan Boeuf on 2018-04-05
def decrypt_file(
        password, in_filename, out_filename=None, chunk_size=24 * 1024):
    """ Decrypts a file using AES (CBC mode) with the
        given password.

        password:
            String used to generate the 32 byte key for
            encryption.

        in_filename:
            Name of the encrypted input file.

        out_filename:
            If None, "<in_filename>strip(.enc)" will be used.
            (i.e. if in_filename is "ABC/aaa.zip.enc" then
            out_filename will be "ABC/aaa.zip").

        chunk_size:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunk_size must be divisible by 16.
    """
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, "rb") as infile:
        origsize = struct.unpack("<Q", infile.read(struct.calcsize("Q")))[0]
        iv = infile.read(16)
        key = hashlib.sha256(password).digest()
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, "wb") as outfile:
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

# -----------------------------------------------------------------------------
def exit_handler(recipients, log_file, archiver_user_name, parameter_list):
    """Sends an outcome email to the recipients about this script.

        Formats the email with the correct subject and message body.
        Is used as exit handler.

     recipients:
        Emails to send this file to, without any checking.

     log_file:
        Log file to attach in case needed to debug.

     archiver_user_name:
        To add to the message body about who archived stuff.

     parameter_list:
        The parameters used in the archiving script,
        including encryption password.

    :return: nothing
    """

    logging.info ("Sending record to %s" % recipients)
    message_body = ("Attached are the latest results from archiving by %s" 
                    "\nAnd the archiving parameters were these" 
                    "\n%s\n" % (archiver_user_name, parameter_list))
    subject = "Data archiving results"
    if "final_archive" in parameter_list:
        if parameter_list["plaintext_archive"]:
            subject = "Success: " + subject
        elif parameter_list["db_success"]:
            subject = "Success: " + subject
        else:
            subject = "Very Almost Success: " + subject
    else:
        subject = "Error: " + subject

    send_email(recipients, subject, message_body, attachments=[log_file])


# -----------------------------------------------------------------------------
def send_email(recipient_list, subject, message_body, attachments=[]):
    """Send provided email message to recipients with provided subject
     and optional attachments.

    Will throw exception if no mail server setup locally.
     recipient_list:
        List or tuple of recipients,
        (all recipients will know who the others are).

     subject:
        What will go in the subject box

     message_body:
        A string that will be plaintext formatted as the message.
        Please include newlines, these will not be added.

     attachments:
        List of file paths to attachments.
        Will ignore files it cannot find.

    :return:
            nothing
    """
    from_mail = "%s@%s" % (getpass.getuser(), socket.getfqdn())
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = from_mail
    msg["To"] = ", ".join(recipient_list)
    msg.attach(MIMEText(message_body, "plain"))

    if attachments:
        if isinstance(attachments, basestring):
            attachments = [attachments]

        for f in attachments:
            if os.path.isfile(f):
                with open(f, "rb") as fil:
                    part = MIMEApplication(
                        fil.read(),
                        Name=os.path.basename(f))

                part["Content-Disposition"] = ("attachment; filename='%s'" %
                                               os.path.basename(f))
                msg.attach(part)
            else:
                logging.info ("File %s not found, will ignore" % f)

    server = smtplib.SMTP("localhost")
    server.sendmail(from_mail, recipient_list, msg.as_string())
    server.quit()


# -----------------------------------------------------------------------------
def add_to_remote_db(
        remote_host, remote_port, remote_database,
        remote_user, remote_password,
        remote_schema, remote_table,
        key_value_dictionary):
    """Generalized function to Insert data into remote database.

        Takes the database connection information and inserts into the
         specified table the specified key value pairs.

     remote_host:
        Ip of the remote machine.

     remote_port:
        Port to connect to.

     remote_database:
        Name of the remote database.

     remote_user:
        Remote user to connect as.

     remote_password:
        Password for remote user.

     remote_schema:
        Remote schema to connect to.

     remote_table:
        Remote table to Insert data into

     key_value_dictionary:
        Dictionary of values to Insert into the remote database.
        Should be use the table fields as the keys.

    :return: True on success
    """

    conn = psycopg2.connect(host=remote_host,
                            port=remote_port,
                            database=remote_database,
                            user=remote_user,
                            password=remote_password)
    conn.autocommit = True

    sql_query = sql.SQL(
        "INSERT INTO {} ({}) VALUES ({})").format(
            sql.SQL(".").join(
                [sql.Identifier(remote_schema), sql.Identifier(remote_table)]),
            sql.SQL(", ").join(
                map(sql.Identifier, dict.keys(key_value_dictionary))),
            sql.SQL(", ").join(
                map(sql.Placeholder, dict.keys(key_value_dictionary))))

    try:
        with conn.cursor() as cursor:
            cursor.execute(sql_query, key_value_dictionary)
    except IOError as (io_errno, strerror):
        logging.error("I/O error({0}): {1}".format(io_errno, strerror))
        return False

    except psycopg2.IntegrityError as integrity:
        logging.error(
            "Database integrity error encountered:\n-->%s", integrity)
        return False

    except psycopg2.DatabaseError as db_error:
        logging.error(
            "Database error encountered:\n-->%s", db_error)
        return False

    except Exception as error_message:
        logging.error(
            "Unknown error occurred:\n-->%s", error_message)
        return False

    finally:
        conn.close()

    return True


# -----------------------------------------------------------------------------
def encryption_info_to_db(
        archive_user, archive_name, password_of_archive,
        db_password):
    """Sends encryption info to specific remote db.

        This function sends the password used for encryption in this
        script with other details to a specific db.
        Hence it only needs that information.

     archive_user:
        User who created the archive

     archive_name:
        Name of the final archive

     password_of_archive:
        Password used to encrypt archive

    :return: True on success
    """

    db_dictionary = {"name_archive": archive_name,
                     "user_archiver": archive_user,
                     "password_archive": password_of_archive}

    return add_to_remote_db(
        remote_host="unknown", remote_port=0,
        remote_database="?", remote_user="?",
        remote_password=db_password, remote_schema="?",
        remote_table="archiving_passwords", key_value_dictionary=db_dictionary)


# -----------------------------------------------------------------------------
def verify_tarball(
        tarball, file_list_checksums=None, deep_check=False,
        delimiter="=", empty_dir_sum="null", alsologtostderr=False):
    """Verify that a tarball is valid, with optional extra checking

    Verifies that a tarball is valid, then with the use of a file list
    can check all the right files are present.
    Also throws an error if files are present or missing from either
    the filelist or tarball.

     tarball:
        Tarball to verify. Can be compressed in a valid tar compression
         format.

     file_list_checksums:
        Optional file list of checksums to check the tarball against

     deep_check:
        (Bool) set if you want to also verify each file against a
        checksum

     delimiter:
        Symbol that separates file path and checksum

    empty_dir_sum:
        Identifier in place of md5sum given to empty directories in the
         file list

     alsologtostderr:
        Be verbose or not

    :return: success or failure as true or false
    """

    broken_tarball = False

    # Basic verification check
    # (return value of 0 is what we want)
    with open(os.devnull, "w") as dev_null:
        basic_result = subprocess.call(
            ["tar", "xfO", tarball], stdout=dev_null, stderr=dev_null)

    if basic_result == 0:
        logging.info(
            "Tarball verified with basic tar extraction check",
            alsologtostderr)
    else:
        logging.error(
            "Tarball not valid, unable to extract."
            "\nTar exit code: %s" % basic_result)
        broken_tarball = True
        return not broken_tarball

    if file_list_checksums is None:
        if deep_check:
            logging.warning(
                "Deep_check was specified without a filelist, will "
                "ignore request for deep check")
            deep_check = False
        logging.warning(
            "Without a specified filelist, only the most basic check "
            "can be completed")
        return not broken_tarball
    else:
        with tarfile.open(tarball, "r") as tar_ball, \
                open(file_list_checksums, "r") as file_list:
            from_file_list = []
            from_tar_list = tar_ball.getnames()
            from_tar_list = [
                entry.rstrip(os.sep) if entry.endswith(os.sep)
                else entry
                for entry in from_tar_list]

            for line in file_list:
                from_file_list.append(line.rstrip().split(delimiter)[0])

            for entry in from_tar_list:
                if not any(
                        entry in test_string
                        for test_string in from_file_list):

                    logging.warning(
                        "File in tarball %s not in filelist", entry)
                    broken_tarball = True

            for entry in from_file_list:
                if entry not in from_tar_list:
                    logging.warning(
                        "File in filelist %s not in tarball", entry)
                    broken_tarball = True

    if (not deep_check) or broken_tarball:
        return not broken_tarball

    else:
        logging.info(
            "Undergoing deep check of tarball, examining all the files")

        # Extract tarball for verification
        with tarfile.open(tarball, "r") as tar_check, \
                open(file_list_checksums, "r") as checksum_list:

            for sum_line in checksum_list:

                file_path, file_hash = sum_line.rstrip().split(delimiter)

                if file_hash != empty_dir_sum:
                    test_file = tar_check.extractfile(file_path)
                    extract_hash = md5_checksum(test_file)

                    if file_hash == extract_hash:
                        logging.info("File %s verified", file_path)
                    else:
                        logging.error(
                            "Something went wrong with file %s while "
                            "verifying tarball"
                            "\nOriginal md5 checksum was: %s,"
                            "\nbut extracted file had checksum of: %s",
                            file_path, file_hash, extract_hash)

                        broken_tarball = True
                        break
                else:
                    logging.info(
                        "'File' is an empty folder and is verified (%s)",
                        file_path)

        return not broken_tarball


# -----------------------------------------------------------------------------
def verify_encrypted_tarball(
        tarball, encryption_password, file_list,
        complete_check=False, sum_delimiter="=",
        empty_dir_sum="null", alsologtostderr=False):
    """ Function to verify tarballs encrypted by this script.

     tarball:
        Tarball to verify.

     encryption_password:
        Password used to encrypt tarball.

     file_list:
        List of files in tarball, preferably with checksums.

     complete_check:
        (Bool) Check each individual file.

     sum_delimiter:
        Symbol that separates file paths from checksums in filelist.

    empty_dir_sum:
        Identifier given to empty directories that are included in the
        tarball file list.

     alsologtostderr:
        (Bool) Be verbose or not.

    :return: Success (True) or Failure (False)
    """
    temp_tarball = tempfile.NamedTemporaryFile(delete=False).name

    decrypt_file(encryption_password, tarball, temp_tarball)
    result = verify_tarball(
        temp_tarball, file_list_checksums=file_list,
        deep_check=complete_check, delimiter=sum_delimiter,
        alsologtostderr=alsologtostderr, empty_dir_sum=empty_dir_sum
        )
    os.remove(temp_tarball)
    return result


# -----------------------------------------------------------------------------
# Written by Jonathan Boeuf on 2018-05-14, largely taken from:
# https://github.com/h4ck3rk3y/recobot/blob/
# 9473237c4e60504a2cfcedcabc82c5efaebe0525/dc_client/pydc_client.py#L1108
def compress_file(
        file_orig, compressor_type, alsologstderr=False, file_compressed=None,
        block_size=1024*900, overwrite_output=False):
    """Compress file with provided compression algorithm.

        Currently only gzip and bzip2 are supported.
        Any compressor that is not supported will default to gzip

     file_orig:
        File to compress

     compressor_type:
        gzip, bzip2, xz or lzma.
        Only gzip and bzip2 currently supported.

     alsologstderr:
        Be verbose or not.

     file_compressed:
        Specified output file if desired.
        Will default to file_orig + compressor suffix

     block_size:
        Specify block size used by compressor, defaults to 1024*900

     overwrite_output:
        If True, overwrite the specified output file or the default
        file if it already exists.

    :return: Success state and output file path
    """

    if os.path.islink(file_orig):
        file_orig = os.path.realpath(file_orig)

    if not os.path.exists(file_orig) or os.path.isdir(file_orig):
        logging.warning(
            "Given file -- %s -- is not a valid file for compression",
            file_orig)
        return False, None

    try:
        file_size_orig = os.path.getsize(file_orig)
    except Exception as exception:
        logging.warning(
            "Unable to get size of given file %s"
            "\nException was %s", file_orig, exception)

        return False, None

    suffixes = (".gz", ".bz2", ".xz", ".lzma")

    if file_compressed is not None:
        if file_compressed.endswith(suffixes):
            logging.info(
                "The compressor will decide the output file (%s) suffix",
                file_compressed)

            file_compressed = file_compressed.rpartition[0] + ".compressor"
    else:
        file_compressed = file_orig + ".compressor"

    def bz_compression(in_file, out_file=None, overwrite=False):
        """Compress file with bzip2"""
        if out_file is None:
            out_file = in_file + ".bz2"
        elif not out_file.endswith(".bz2"):
            out_file = out_file + ".bz2"

        if not os.path.exists(os.path.dirname(out_file)):
            logging.error(
                "Folder to place compressed file in %s does not exist",
                out_file)
            return False, out_file
        elif os.path.exists(out_file):
            if overwrite:
                logging.warning("Output file %s will be overwritten", out_file)
            else:
                logging.error(
                    "Output file %s already exists, will not overwrite",
                    out_file)
                return False, out_file

        bz_compressor = bz2.BZ2Compressor()

        with open(out_file, "wb") as out_stream, \
                open(in_file, "rb") as input_stream:
            try:
                for blocks in range(
                        int(math.ceil(float(file_size_orig) / block_size))):

                    out_stream.write(
                        bz_compressor.compress(input_stream.read(block_size)))

                out_stream.write(bz_compressor.flush())

            except IOError as io:
                logging.error(
                    "I/O error occurred; compression failed."
                    "\nError was %s", io)
                return False, out_file

            except Exception as ex:
                logging.error(
                    "Unexpected error occurred; compression failed."
                    "\nError was %s", ex)
                return False, out_file

        return True, out_file

    def gz_compression(in_file, out_file=None, overwrite=False):
        """Compress file using gzip"""
        if out_file is None:
            out_file = in_file + ".gz"
        elif not out_file.endswith(".gz"):
            out_file = out_file + ".gz"

        if not os.path.exists(os.path.dirname(out_file)):
            logging.error(
                "Folder to place compressed file in %s does not exist",
                out_file)
            return False, out_file

        elif os.path.exists(out_file):
            if overwrite:
                logging.warning(
                    "Output file %s will be overwritten", out_file)
            else:
                logging.error(
                    "Output file %s already exists, will not overwrite",
                    out_file)
                return False, out_file

        input_stream = open(in_file, "rb")
        out_stream = gzip.open(out_file, "wb")
        try:
            shutil.copyfileobj(input_stream, out_stream)

        except IOError as io:
            logging.error("I/O error occurred; compression failed.\n"
                          "Error was %s", io)
            return False, out_file

        except Exception as ex:
            logging.error("Unexpected error occurred; compression failed.\n"
                          "Error was %s", ex)
            return False, out_file

        finally:
            input_stream.close()
            out_stream.close()

        return True, out_file

    def xz_compression(in_file, out_file=None, overwrite=False):
        """Compress file with xz (not currently supported)"""
        help_string = (
            "XZ compression not currently supported by this script "
            "(but is by tar), will default to gzip")

        logging.info(help_string, alsologstderr)
        return gz_compression(in_file, out_file, overwrite)

    def lzma_compression(in_file, out_file=None, overwrite=False):
        """Compress file with LZMA (not currently supported)"""
        help_string = (
            "LZMA compression is depreciated, and has been superseded "
            "by XZ compression."
            "\nWill use XZ compression, although LZMA is still "
            "supported by tar.")

        logging.info(help_string, alsologstderr)
        return xz_compression(in_file, out_file, overwrite)

    valid_compression_types = {
        "gzip": gz_compression,
        "bzip2": bz_compression,
        "lzma": lzma_compression,
        "xz": xz_compression
    }

    if compressor_type in valid_compression_types:
        return valid_compression_types.get(compressor_type, gz_compression)(
            file_orig, file_compressed[:-len(".compressor")], overwrite_output)
    else:
        logging.warning(
            "Compressor type: %s"
            "\nIs invalid, will use the default (gzip)", compressor_type)
        return valid_compression_types.get("gzip")(
            file_orig, file_compressed[:-len(".compressor")], overwrite_output)


# -----------------------------------------------------------------------------
if __name__ == "__main__":
    usage = "Create a compressed and encrypted archive of a folder."
    parser = argparse.ArgumentParser(usage=usage)

    parser.add_argument(
        "--print_cmds_only", action="store_true", dest="print_cmds_only",
        default=False, help="Only print the commands that would be executed")

    parser.add_argument(
        "-v", "--alsologtostderr", action="store_true",
        dest="alsologtostderr", default=False,
        help="Also log standard error to console")

    parser.add_argument(
        "-p", "--plain_text", action="store_true",
        dest="plain_text", default=False,
        help="Set this flag to not encrypt the archive. ***NOT RECOMMENDED**")

    parser.add_argument(
        "-o", "--output_folder", action="store", dest="output_folder",
        help="Folder to save the output archive in. "
             "If not specified, archive will be created next to original file")

    parser.add_argument(
        "-i", "--input_folder", action="store", dest="input_folder",
        help="Folder to create an archive of")

    parser.add_argument(
        "-a", "--archive_name", action="store", dest="archive_name",
        help="Root name of the archive files, if different from input folder")

    parser.add_argument(
        "-d", "--remote_db_password", action="store",
        dest="remote_db_password", default="",
        help="Password for remote database, "
             "not required for plain text archive.")

    parser.add_argument(
        "-c", "--compressor", action="store", dest="compressor",
        default="bzip2", help="Compression to use on archive.")

    args = parser.parse_args()

    # Set up logging
    current_logfile = setup_logging("ArchiveProjectData", args.alsologtostderr)

    logging.info(
        "*---Python version:---*\n%s\n" % sys.version, args.alsologtostderr)

    # Show help message if no arguments specified
    if not len(sys.argv) > 1:
        print ("This script requires arguments")
        parser.print_help(sys.stderr)
        os.remove(current_logfile)
        sys.exit(2)

    # Print_cmds_workaround
    if args.print_cmds_only:
        logging.critical(
            "print_cmds_only not implemented, will exit.")
        os.remove(current_logfile)
        sys.exit(2)

    # Verify input folder to archive
    if args.input_folder is None:
        logging.critical(
            "No folder specified for archiving, please use -i --input_folder")
        os.remove(current_logfile)
        sys.exit(2)

    # Search paths for input folder (to be used later)
    # If this is placed before the error checking,
    # it can cause dirty crash in case of error.
    archive_file_paths = [
        os.path.abspath(args.input_folder),
        os.curdir
        ]

    valid_archive_input = False
    input_archive_folder = args.input_folder.rstrip(os.sep)

    # Verify we have a sensible input, no funky characters
    if not input_archive_folder.translate(None, "-_/").isalnum():
        logging.critical(
            "Folder name to archive "
            "\n%s "
            "\ncontains characters that are not alphanumeric, "
            "hyphens or dashes. This is either wrong, a hidden folder, a file "
            "or a badly named folder. Please fix this before continuing.",
            input_archive_folder)
        os.remove(current_logfile)
        sys.exit(2)

    # Try and find the folder you are talking about
    for path in archive_file_paths:
        if os.path.exists(os.path.join(path, input_archive_folder)):
            valid_archive_input = True
            input_archive_folder = os.path.join(path, input_archive_folder)
            break

    # Create dictionary to store the full/adapted parameters
    archive_parameters = {}

    if valid_archive_input:
        logging.info(
            "Thank you for the valid folder to archive: %s"
            % input_archive_folder, args.alsologtostderr)
        stat_info = os.stat(input_archive_folder)
        if not os.listdir(input_archive_folder):
            logging.critical(
                "But folder %s appears to be empty, will not continue",
                input_archive_folder)
            os.remove(current_logfile)
            sys.exit(1)

        elif not stat_info.st_uid == os.getuid():
            logging.critical(
                "This user do not own this folder, it is owned by %s, uid %s. "
                "This user %s, uid %s should own the folder, terminating...",
                pwd.getpwuid(stat_info.st_uid)[0],
                stat_info.st_uid, pwd.getpwuid(os.getuid())[0], os.getuid())

            os.remove(current_logfile)
            sys.exit(1)

        elif not (os.access(input_archive_folder, os.W_OK) and
                  os.access(input_archive_folder, os.R_OK)):
            logging.critical(
                "This script does not have r/w permission for this folder")
            logging.info(
                "Folder has permissions of %s for %s:%s" %
                (oct(stat_info[stat.ST_MODE])[-3:],
                 pwd.getpwuid(stat_info[stat.ST_UID]).pw_name,
                 grp.getgrgid(stat_info[stat.ST_GID]).gr_name),
                args.alsologtostderr)

            os.remove(current_logfile)
            sys.exit(1)

        else:
            archive_parameters["folder_to_archive"] = input_archive_folder
    else:
        logging.critical(
            "Cannot find path to %s, please check folder name "
            "or give absolute path", input_archive_folder)
        os.remove(current_logfile)
        sys.exit(2)

    # Verify where to place archive, if given
    valid_archive_output_folder = False
    output_archive_location = os.path.dirname(input_archive_folder)

    if args.output_folder is not None:
        if not args.output_folder.translate(None, "-_/").isalnum():
            logging.warning(
                "Folder to place archive in "
                "\n%s "
                "\ncontains characters that are not alphanumeric, hyphens or "
                "dashes.\nWill use system default %s",
                args.output_folder, output_archive_location)

        else:
            archive_file_paths.insert(1, output_archive_location)

            for path in archive_file_paths:
                if os.path.exists(os.path.join(
                        path, args.output_folder.rstrip(os.sep))):

                    valid_archive_output_folder = True
                    output_archive_location = os.path.join(
                        path, args.output_folder.rstrip(os.sep))
                    break

            test_list = [archive_parameters["folder_to_archive"],
                         output_archive_location
                         ]
            if archive_parameters["folder_to_archive"] in \
                    os.path.commonprefix(test_list):

                valid_archive_output_folder = False
                output_archive_location = os.path.dirname(
                    archive_parameters["folder_to_archive"])

                logging.error(
                    "Specified output location of the archive found, but is "
                    "within the folder to archive. This is not good, user is "
                    "lucky it was spotted.")

            if valid_archive_output_folder:
                logging.info ("Output folder found at %s, will place archive there" %
                       output_archive_location)
            else:
                logging.warning(
                    "Cannot find valid output_folder path for %s, will create "
                    "archive next to original folder in %s",
                    args.output_folder, output_archive_location)

    archive_parameters["folder_to_place_archive"] = output_archive_location

    # Verify what to call archive, if given.
    output_archive_name = os.path.join(
        archive_parameters["folder_to_place_archive"],
        os.path.basename(archive_parameters["folder_to_archive"])) + ".tar"
    output_archive_name_default = output_archive_name

    if args.archive_name is not None:
        if args.archive_name.endswith(".tar"):
            output_archive_name = args.archive_name[:-4]

        else:
            output_archive_name = args.archive_name

        # Check input is just a name, no funny characters
        if output_archive_name.translate(None, "-_").isalnum():
            if os.path.exists(os.path.join(
                    archive_parameters["folder_to_place_archive"],
                    output_archive_name) + ".tar"):

                logging.warning(
                    "User given archive name %s already exists within %s"
                    "\nUsing system generated name",
                    output_archive_name,
                    archive_parameters["folder_to_place_archive"])

                output_archive_name = output_archive_name_default

            else:
                output_archive_name = os.path.join(
                    archive_parameters["folder_to_place_archive"],
                    output_archive_name) + ".tar"
        else:
            logging.warning(
                "User given archive name \n%s"
                "\nis not valid, it may only contain alphanumeric characters, "
                "hyphens or dashes."
                "\nWill use system generated name:  %s",
                output_archive_name,
                os.path.basename(
                    archive_parameters["folder_to_archive"]) + ".tar")

            output_archive_name = output_archive_name_default

    if (output_archive_name == output_archive_name_default and
            os.path.exists(output_archive_name_default)):

        logging.critical(
            "File named %s already exists, and user has not specified valid "
            "alternative archive name."
            "\n====>Altering the output folder (-o) or specifying an archive "
            "name (-a) might solve this",
            output_archive_name_default)

        os.remove(current_logfile)
        sys.exit(2)

    # Verify user wants a plaintext archive
    if args.plain_text:
        print ("And user specified not to encrypt archive. "
               "This is not recommended.")
        if query_yes_no(
                "Would you like to encrypt the archive after all?",
                default="no") == "yes":

            args.plain_text = False
            logging.info("User has been prompted, and changed argument of "
                       "plaintext from True to False",
                       args.alsologtostderr)

            logging.info("User should provide the password to "
                       "connect to the database with.", args.alsologtostderr)

            if args.remote_db_password is "":
                args.remote_db_password = get_password(
                    reason="remote database connection", tries=3,
                    min_length=24)

    if not (args.plain_text or args.remote_db_password):
        logging.critical(
            "Encrypted archive specified, but no password for "
            "the remote database provided.")

        logging.info("The db password is needed to store the encryption password."
              "\nWithout this, we could end up with no one being able to "
              "recover this archive."
              "\nTalk to sysadmin if you are not sure what to do.")
        os.remove(current_logfile)
        sys.exit(2)

    # Check if we might overwrite any files by accident
    valid_compression = {"gzip": ".gz", "bzip2": ".bz2",
                         "lzma": ".lzma", "xz": ".xz"}
    compress_out = (output_archive_name +
                    valid_compression.get(args.compressor, "gzip"))

    encrypt_out = compress_out + ".enc"

    if os.path.exists(compress_out):
        logging.critical("Output file %s already exists."
                         "\nPlease deal with this and try again", compress_out)
        os.remove(current_logfile)
        sys.exit(2)

    if not args.plain_text and os.path.exists(encrypt_out):
        logging.critical("Output file %s already exists."
                         "\nPlease deal with this and try again", encrypt_out)
        os.remove(current_logfile)
        sys.exit(2)

    archive_parameters["full_path_of_archive"] = output_archive_name

    archive_parameters["archive_file_list"] = (
            archive_parameters["full_path_of_archive"][:-4] + ".filelist"
    )

    if os.path.exists(archive_parameters["archive_file_list"]):
        logging.critical(
            "File list %s already exists, please deal with the problem."
            % archive_parameters["archive_file_list"])
        os.remove(current_logfile)
        sys.exit(1)

    archive_parameters["plaintext_archive"] = args.plain_text

    # Get name of user
    sys.stdout.write("Please enter your robots email name.\n"
                     "e.g for 'pauln@robots.ox.ac.uk', please enter 'pauln':")
    empty_user = True
    while empty_user:
        user = raw_input().lower()
        if user.isalpha():
            sys.stdout.write("Thank you %s\n" % user)
            archive_parameters["archive_user"] = user
            empty_user = False
        else:
            sys.stdout.write("Please use only letters:")

    # Register exit handler here, so Sysadmin doesn"t get spammed with people
    # figuring out the script
    atexit.register(
        exit_handler,
        recipients=["archivers@oxfordrobotics.institute",
                    "%s@robots.ox.ac.uk" % archive_parameters["archive_user"]],
        log_file=current_logfile,
        archiver_user_name=archive_parameters["archive_user"],
        parameter_list=archive_parameters)

    # Output variables, confirm  no encryption if set, and confirm continuation
    logging.info(
        "====> These are the parameters this script will use:",
        args.alsologtostderr)

    logging.info(pprint.pformat(archive_parameters), args.alsologtostderr)

    if query_yes_no("Do you wish to continue?", default="yes") == "no":
        logging.info ("Terminating......")
        logging.info(
            "User %s decided to abort the process."
            % archive_parameters["archive_user"])

        os.remove(current_logfile)
        sys.exit(2)


    # Input password
    if not archive_parameters["plaintext_archive"]:
        archive_password = get_password(
            reason="archive encryption",
            tries=3,
            min_length=16)

        if not archive_password:
            logging.critical(
                "Unable to get valid password from user. "
                "Terminating archiving procedure.")
            sys.exit(1)
        else:
            archive_parameters["archive_encryption_password"] = \
                archive_password

    # Clean the archive folder of junk files we don"t want
    logging.info ("Removing unwanted and redundant files....")
    clean_folder(archive_parameters["folder_to_archive"], read_only=False)

    # Create a file list
    logging.info(
        "Creating file list with md5 checksums %s"
        % archive_parameters["archive_file_list"],
        args.alsologtostderr)

    create_filelist_with_checksums(
        archive_parameters["folder_to_archive"],
        archive_parameters["archive_file_list"],
        "=", True)

    logging.info(
        "Filelist with checksums created: %s"
        % archive_parameters["archive_file_list"], args.alsologtostderr)

    # Create the tarfile
    logging.info (
            "Starting to create tarfile %s"
            % archive_parameters["full_path_of_archive"])

    with tarfile.open(
            archive_parameters["full_path_of_archive"], mode="w") as archive:

        archive.add(
            archive_parameters["folder_to_archive"], recursive=True,
            arcname=os.path.basename(archive_parameters["folder_to_archive"]))

    logging.info(
        "Tar file %s successfully created"
        % archive_parameters["full_path_of_archive"], args.alsologtostderr)

    # Verify uncompressed tarball
    archive_parameters["uncompressed_verification"] = verify_tarball(
        archive_parameters["full_path_of_archive"],
        file_list_checksums=archive_parameters["archive_file_list"],
        deep_check=True, alsologtostderr=args.alsologtostderr)

    if archive_parameters["uncompressed_verification"]:
        logging.info("Uncompressed tarball verified", args.alsologtostderr)
    else:
        logging.critical(
            "Uncompressed tarball not verified, something went wrong")

        logging.info("archiving parameters are %s", archive_parameters)
        sys.exit(1)

    # Create compressed tarfile
    (compression_success,
     archive_parameters["full_path_of_compressed_archive"]) \
        = compress_file(
        archive_parameters["full_path_of_archive"], args.compressor,
        args.alsologtostderr, overwrite_output=False)

    if compression_success:
        logging.info(
            "Compressed tar file %s successfully created"
            % archive_parameters["full_path_of_compressed_archive"],
            args.alsologtostderr)
    else:
        logging.error(
            "Creation of compressed file %s failed.",
            archive_parameters["full_path_of_compressed_archive"])
        sys.exit(1)

    # Verify compressed tarball
    archive_parameters["compressed_verification"] = verify_tarball(
        archive_parameters["full_path_of_compressed_archive"],
        file_list_checksums=archive_parameters["archive_file_list"],
        deep_check=True, alsologtostderr=args.alsologtostderr)

    if archive_parameters["compressed_verification"]:
        logging.info("Compressed tarball verified", args.alsologtostderr)
    else:
        logging.critical(
            "Compressed tarball not verified, something went wrong")
        logging.info("archiving parameters are %s", archive_parameters)
        sys.exit(1)

    logging.info(
        "Removing uncompressed tar %s as compressed archive has been verified"
        % archive_parameters["full_path_of_archive"], args.alsologtostderr)

    os.remove(archive_parameters["full_path_of_archive"])

    if (not archive_parameters["plaintext_archive"] and
            "archive_encryption_password" in archive_parameters):

        # Encrypt archive
        archive_parameters["full_path_of_encrypted_archive"] = \
            archive_parameters["full_path_of_compressed_archive"] + ".enc"

        encrypt_file(archive_parameters["archive_encryption_password"],
                     archive_parameters["full_path_of_compressed_archive"],
                     archive_parameters["full_path_of_encrypted_archive"])

        logging.info(
            "Encrypted compressed tar file %s created"
            % archive_parameters["full_path_of_encrypted_archive"],
            args.alsologtostderr)

        # Verify encrypted archive by decrypting
        archive_parameters["encrypted_verification"] = \
            verify_encrypted_tarball(
            archive_parameters["full_path_of_encrypted_archive"],
            archive_parameters["archive_encryption_password"],
            archive_parameters["archive_file_list"], complete_check=True,
            sum_delimiter="=", alsologtostderr=args.alsologtostderr)

        if archive_parameters["encrypted_verification"]:
            logging.info("Encrypted tarball verified", args.alsologtostderr)
        else:
            logging.critical(
                "Encrypted tarball not verified, something went wrong")
            logging.info("archiving parameters are %s", archive_parameters)
            sys.exit(1)

        logging.info(
            "Removing unencrypted compressed tar %s "
            "as encrypted archive has been verified"
            % archive_parameters["full_path_of_compressed_archive"],
            args.alsologtostderr)

        os.remove(archive_parameters["full_path_of_compressed_archive"])

    if archive_parameters["plaintext_archive"]:
        archive_parameters["final_archive"] = \
            archive_parameters["full_path_of_compressed_archive"]
    else:
        archive_parameters["final_archive"] = \
            archive_parameters["full_path_of_encrypted_archive"]

        archive_parameters["db_success"] = encryption_info_to_db(
            archive_parameters["archive_user"],
            os.path.basename(archive_parameters["final_archive"]),
            archive_parameters["archive_encryption_password"],
            args.remote_db_password)

    logging.info(
        "Archive successfully created, will send notification email",
        args.alsologtostderr)
    # Script will exit, and exit handler will be called to send email
