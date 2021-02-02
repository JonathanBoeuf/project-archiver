#!/usr/bin/env python2

import argparse
import datetime
import logging
import multiprocessing
import os
import yaml
import sys
import time

from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive

from CreateArchive import setup_logging
from CreateArchive import md5_checksum


# found here: https://stackoverflow.com/a/28666223
def number_to_base(n, b):
    """Convert number n to base b
    n:

    b:

    :return: numeric list of numbers
    """

    if n == 0:
        return [0]
    digits = []
    while n:
        digits.append(int(n % b))
        n /= b  # //= for python 3
    return digits[::-1]


def read_chunk(input_file, chunk_size, start_position):
    """

    :return:
    """
    # check if file or file handle and behave appropriately
    close_file = False
    fh = "Empty file handle"
    try:
        if isinstance(input_file, basestring):
            if (os.path.exists(input_file)
                    and not os.path.isdir(os.path.abspath(input_file))):
                fh = open(input_file, "rb")
                close_file = True
            else:
                return ''
        else:
            fh = input_file
        fh.seek(start_position)
        chunk = fh.read(chunk_size)
        return chunk

    finally:
        if close_file:
            fh.close()


def generate_file_chunks(input_file, chunk_size):
    """

    :param input_file:
    :param chunk_size:
    :return:
    """
    with open(input_file, "rb") as f:
        while True:
            chunk_start = f.tell()
            new_chunk = read_chunk(f, chunk_size, chunk_start)
            if new_chunk == '':
                break
            yield new_chunk


def create_split_file_name(str_length, iterator, root_folder):
    """

    :param str_length:
    :param iterator:
    :param root_folder:
    :return:
    """

    string_to_number = number_to_base(iterator, 26)
    string_list = [0] * (str_length - len(string_to_number)) + string_to_number
    string_list = ["x"] + [chr(97+e) for e in string_list]
    return os.path.join(root_folder, "" + "".join(string_list))


def provide_chunks_for_queues(input_file, chunk_size, root_folder, process_limit):
    """

    :param input_file:
    :param chunk_size:
    :param root_folder:
    :param process_limit:
    :return:
    """

    file_total = (os.stat(input_file).st_size + (chunk_size - 1)) / chunk_size
    name_length = (len(number_to_base(file_total, 26)) + 1)
    file_iterator = 0
    for c in generate_file_chunks(input_file, chunk_size):
        if c == '':
            break
        else:
            name = create_split_file_name(name_length, file_iterator, root_folder)
            yield (name, c)
            file_iterator += 1
    for end in range(0, process_limit, 1):
        yield "STOP"


def queue_chunks(queue, input_file, root_folder, num_processes,
                 chunk_size=500*1024*1024, nice_level=10):
    """

    :param queue:
    :param input_file:
    :param root_folder:
    :param num_processes:
    :param chunk_size:
    :param nice_level:
    :return:
    """
    current_nice = os.nice(0)
    os.nice(nice_level-current_nice)
    for new_chunk in provide_chunks_for_queues(input_file, chunk_size, root_folder, num_processes):
        queue.put(new_chunk)


def write_split_file(file_name, binary_chunk):
    """

    :param file_name:
    :param binary_chunk:
    :return:
    """

    with open(file_name, 'wb') as file_obj:
        file_obj.write(binary_chunk)


def create_split_files(in_queue, out_queue, nice_level=12):
    """

    :param in_queue:
    :param out_queue:
    :param nice_level:
    :return:
    """

    current_nice = os.nice(0)
    os.nice(nice_level-current_nice)
    for data in iter(in_queue.get, "STOP"):
        write_split_file(*data)
        out_data = (data[0], md5_checksum(data[0]))
        out_queue.put(out_data)
    out_queue.put("STOP")
    return None


def authenticate_gdrive(credentials):
    """

    :param credentials:
    :return:
    """

    gauth = GoogleAuth()

    if credentials is None or credentials == "":
        logging.critical("Credentials not provided for gdrive authentication")
        return None

    if not os.path.isfile(credentials):
        logging.critical(
            "Provided credentials file %s cannot be found", credentials)

    # Try to load saved client credentials
    gauth.LoadCredentialsFile(os.path.abspath(credentials))

    if gauth.credentials is None:
        # Authenticate if they're not there
        gauth.LocalWebserverAuth()

    elif gauth.access_token_expired:
        # Refresh them if expired
        gauth.Refresh()

    else:
        # Initialize the saved credentials
        gauth.Authorize()
        # Save the current credentials to a file
        gauth.SaveCredentialsFile(credentials)

    return GoogleDrive(gauth)


def validate_gdrive_parent_folders(parent_folders):
    """

    :param parent_folders:
    :return:
    """
    if isinstance(parent_folders, basestring):
        parent_folders = [{"id": parent_folders}]
        return parent_folders
    elif isinstance(parent_folders, list):
        if parent_folders[0] is dict:
            if not any(f.haskey("id") for f in parent_folders):
                logging.error("Invalid format of parent folders, will default to root as parent")
                parent_folders = [{"id": 'root'}]
                return parent_folders

            if not all(f.haskey("id") for f in parent_folders):
                logging.warning("Not all entries in parent folders are correctly formatted, they will be ignored.")

                logging.info("Badly formatted entries are:"
                             "\n%s", [f for f in parent_folders if not f.haskey("id")])

                parent_folders = [f for f in parent_folders if f.haskey("id")]
                return parent_folders
        else:
            parent_folders = [{"id": str(folder)} for folder in parent_folders]
            return parent_folders

    else:
        logging.error("parent folders neither string or list, no idea what to do here, will default to root as parent.")
        return [{"id": 'root'}]


def create_new_gdrive_folder(drive_handle, folder_name, parents):
    """

    :param drive_handle:
    :param folder_name:
    :param parents:
    :return:
    """
    if not isinstance(folder_name, basestring):
        folder_name = str(folder_name)

    parents = validate_gdrive_parent_folders(parents)

    file_list = drive_handle.ListFile({
        'q': "'%s' in parents and trashed=false" % parents}).GetList()

    if any(file_1['title'] == folder_name for file_1 in file_list):
        logging.error("Folder with title %s already exists, will not create confusion")
        return None

    new_folder = drive_handle.CreateFile(
        {'title': folder_name, "parents": parents,
         "mimeType": "application/vnd.google-apps.folder"})

    new_folder.Upload()
    return new_folder["id"]


def create_gdrive_archive_folder(drive_handle, archive_name, data_archive_parent_folder):
    """

    :param drive_handle:
    :param archive_name:
    :param data_archive_parent_folder:
    :return:
    """

    file_list = drive_handle.ListFile(
        {'q': "'%s' in parents and trashed=false"
              % data_archive_parent_folder}).GetList()

    year_now = str(datetime.datetime.now().year)
    year_folder_id = next((
        file_1['id'] for file_1 in file_list if file_1['title'] == year_now),
        None)

    if year_folder_id is None:
        year_folder_id = create_new_gdrive_folder(
            drive_handle=drive_handle, folder_name=year_now,
            parents=[{'id': data_archive_parent_folder}])

    return create_new_gdrive_folder(
        drive_handle=drive_handle, folder_name=archive_name,
        parents=[{'id': year_folder_id}])


def upload_file_to_gdrive(drive_handle, file_path, parent_folder=[{'id': 'root'}], local_file_checksum="", upload_file_name=""):
    """

    :param drive_handle:
    :param file_path:
    :param parent_folder:
    :param local_file_checksum:
    :param upload_file_name:
    :return:
    """

    if upload_file_name == "":
        upload_file_name = os.path.basename(file_path)

    parent_folder = validate_gdrive_parent_folders(parent_folder)

    if local_file_checksum == "":
        local_file_checksum = md5_checksum(file_path)
    elif not local_file_checksum == md5_checksum(file_path):
        local_file_checksum = md5_checksum(file_path)

    new_file = drive_handle.CreateFile({'title': upload_file_name, 'parents': parent_folder})
    new_file.SetContentFile(file_path)
    upload_success = False
    upload_tries = 0
    while (not upload_success) and (upload_tries < 20):
        try:
            new_file.Upload()
            new_file.FetchMetadata()
        except:
            logging.warning("Upload and or Fetchmetadata failed, will try again")
            time.sleep(5*2**upload_tries)
            upload_tries = +1
            continue

        if new_file['md5Checksum'] == local_file_checksum:
            logging.info ("upload successful")
            upload_success = True
        else:
            logging.info ("upload unsuccessful")
            logging.info ("local checksum is %s" % local_file_checksum)
            logging.info ("Remote_checksum is %s" % new_file['md5Checksum'])
            upload_tries = +1

    return new_file['id']


def upload_archive_parts_to_gdrive(drive_handle, input_queue, upload_folder,
                                   nice_level=15):
    """

    :param drive_handle:
    :param input_queue:
    :param upload_folder:
    :param nice_level:
    :return:
    """

    current_nice = os.nice(0)
    os.nice(nice_level-current_nice)

    for data in iter(input_queue.get, "STOP"):
        upload_file_to_gdrive(
            drive_handle=drive_handle, file_path=data[0],
            parent_folder=[{'id': upload_folder}],
            local_file_checksum=data[1], upload_file_name="")
    return None


def load_configuration(config_file):
    """
    
    :param config_file:
    :return:
    """
    config_file = os.path.abspath(config_file)

    if not os.path.isfile(config_file):
        logging.error(
            "Configuration file %s is not an existing file" % config_file)
        return None

    with open(config_file, "r") as in_fh:
        config_dict = yaml.safe_load(in_fh)

        if config_dict is None:
            logging.error(
                "Config %s is empty" % config_file)

        return config_dict


if __name__ == '__main__':
    usage = "Split and Upload an archive to google drive.\n" \
            "Assumes the archive was created by the CreateArchive script," \
            "and has a corresponding filelist."
    parser = argparse.ArgumentParser(usage=usage)

    parser.add_argument("-v", "--alsologtostderr", action="store_true",
                        dest="alsologtostderr", default=False,
                        help="Also log errors to console")

    parser.add_argument("-a", "--archive", action="store", dest="archive",
                        help="Archive to split and upload")

    parser.add_argument("--print_cmds_only", action="store_true",
                        dest="print_cmds_only", default=False,
                        help="Only print the commands that would be executed")

    args = parser.parse_args()

    # Set up logging
    current_logfile = setup_logging("UploadArchive", args.alsologtostderr)

    # Show help message if no arguments specified
    if not len(sys.argv) > 1:
        print ("This script requires arguments")
        parser.print_help(sys.stdout)
        os.remove(current_logfile)
        sys.exit(2)

    # Verify archive to upload
    if args.archive is None:
        logging.critical(
            "No archive specified for upload, please use -a, --archive")
        os.remove(current_logfile)
        sys.exit(2)

    archive_file_paths = [
        os.curdir,
        os.path.expanduser('~')
        ]

    valid_archive_input = False

    # Try and find the folder you are talking about
    if os.path.exists(os.path.abspath(args.archive)):
        valid_archive_input = True
        args.archive = os.path.abspath(args.archive)
    else:
        for path in archive_file_paths:
            if os.path.exists(os.path.join(path, args.archive)):
                valid_archive_input = True
                args.archive = os.path.join(path, args.archive)
                break

    if valid_archive_input:
        logging.info("Thank you for a valid archive: %s" % args.archive)

    else:
        logging.critical(
            "Cannot find path to %s, please check folder name "
            "or give absolute path", args.archive)
        os.remove(current_logfile)
        sys.exit(2)

    logging.info("Number of cpu cores : %s", multiprocessing.cpu_count())
    pool_size = multiprocessing.cpu_count()
    if not args.print_cmds_only:
        logging.info(
            "Using number of cpu cores: %s", pool_size)
    else:
        logging.info("Would use this many cpu cores: %s" % pool_size)

    if not args.print_cmds_only:
        process_pool = multiprocessing.Pool(pool_size)
        process_manager = multiprocessing.Manager()
        split_data_queue = process_manager.Queue(20)
        file_paths_queue = process_manager.Queue(40)

    project_name = (os.path.basename(args.archive)).split(".")[0]
    project_filelist = os.path.join(
        os.path.dirname(args.archive),
        "".join((project_name, ".filelist")))

    if os.path.isfile(project_filelist):
        logging.info("Found file list %s ", project_filelist)
    else:
        logging.critical("Unable to find filelist next to archive, "
                         "\nPlease rectify and try again")
        os.remove(current_logfile)
        sys.exit(1)

    archive_parts_folder = "".join((
        project_name, "-",
        datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"),
        "-parts"))
    archive_parts_folder = os.path.join(
        os.path.dirname(args.archive), archive_parts_folder)

    if not args.print_cmds_only:
        os.mkdir(archive_parts_folder, 0o777)
        if os.path.isdir(archive_parts_folder):
            logging.info("Archive pieces folder %s successfully created"
                         % archive_parts_folder)
        else:
            logging.critical("Unable to create folder %s."
                             "\nTerminating...")
            os.remove(current_logfile)
            sys.exit(1)
    else:
        logging.info("Would make Archive pieces folder %s " % archive_parts_folder)

    config = load_configuration(
        os.path.join(os.path.dirname(__file__), "upload_config.yaml"))

    if not args.print_cmds_only:
        logging.info("Authenticating with Google drive....")
        drive = authenticate_gdrive("credentials.json")

        logging.info(
            "Creating remote archive folder %s" % project_name)
        remote_archive_folder = create_gdrive_archive_folder(
            drive_handle=drive, archive_name=project_name,
            data_archive_parent_folder=config["data_archive_folder_id"])
        logging.info(
            "Finished creating remote archive folder %s" % project_name)
    else:
        logging.info(
            "Authenticate with google drive and create archive folder %s" %
            project_name)

    if not args.print_cmds_only:
        if remote_archive_folder is None:
            logging.critical(
                "Something has gone wrong, could not create new remote archive "
                "folder for %s" % project_name)
            sys.exit(1)

        queue_task = multiprocessing.Process(
            target=queue_chunks, args=(
                split_data_queue, args.archive, archive_parts_folder, pool_size))
        queue_task.start()

        jobs = []
        for i in range(0, max(pool_size/2, 1), 1):
            p = multiprocessing.Process(
                target=create_split_files, args=(
                    split_data_queue, file_paths_queue))
            jobs.append(p)
            p.start()

        for i in range(0, max(pool_size/2, 1), 1):
            p = multiprocessing.Process(
                target=upload_archive_parts_to_gdrive, args=(
                    drive, file_paths_queue, remote_archive_folder))
            jobs.append(p)
            p.start()

        p = upload_file_to_gdrive(
            drive_handle=drive, file_path=project_filelist,
            parent_folder=[{'id': remote_archive_folder}], local_file_checksum="",
            upload_file_name="")
        jobs.append(p)
        p.start()

        queue_task.join()
        for job in jobs:
            job.join()
        logging.info("Script has finished")
    else:
        logging.info("Script would now, in parallel, split the archive into chunks,"
              "pass those chunks to be uploaded via a queue, and finish.")
