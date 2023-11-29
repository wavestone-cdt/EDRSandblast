import argparse
import csv
import os

from requests import get
from gzip import decompress
from json import loads

from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from lightpdbparser import Pdb

from pefile import PE, DIRECTORY_ENTRY, PEFormatError

THREADS_LIMIT = None
CSVLock = threading.Lock()

machineType = dict(x86=332, x64=34404)
supported_images = ["ntoskrnl.exe", "wdigest.dll", "ci.dll", "fltmgr.sys"]
modes = [image_name.split(".")[0] for image_name in supported_images]
extensions_by_mode = dict(image_name.split(".") for image_name in supported_images)
known_image_versions = {mode: list() for mode in modes}
modes_by_imagename = dict(zip(supported_images, modes))
csvFilenameByMode = {mode: mode.capitalize() + "Offsets.csv" for mode in modes}

symbols = dict(
    ntoskrnl=[
        ("PspCreateProcessNotifyRoutine", "symbol"),
        ("PspCreateThreadNotifyRoutine", "symbol"),
        ("PspLoadImageNotifyRoutine", "symbol"),
        ("_EPROCESS", "Protection", "field"),
        ("EtwThreatIntProvRegHandle", "symbol"),
        ("_ETW_REG_ENTRY", "GuidEntry", "field"),
        ("_ETW_GUID_ENTRY", "ProviderEnableInfo", "field"),
        ("PsProcessType", "symbol"),
        ("PsThreadType", "symbol"),
        ("_OBJECT_TYPE", "CallbackList", "field"),
        ("SeCiCallbacks", "symbol"),
    ],
    wdigest=[
        ("g_fParameter_UseLogonCredential", "symbol"),
        ("g_IsCredGuardEnabled", "symbol"),
    ],
    ci=[
        ("g_CiOptions", "symbol"),
        ("CiValidateImageHeader", "symbol"),
    ],
    fltmgr=[
        ("FltGlobals", "symbol"),
        ("_GLOBALS", "FrameList", "field"),
        ("_FLT_RESOURCE_LIST_HEAD", "rList", "field"),
        ("_FLTP_FRAME", "Links", "field"),
        ("_FLTP_FRAME", "RegisteredFilters", "field"),
        ("_FLT_OBJECT", "PrimaryLink", "field"),
        ("_FLT_FILTER", "DriverObject", "field"),
        ("_FLT_FILTER", "InstanceList", "field"),
        ("_DRIVER_OBJECT", "DriverInit", "field"),
        ("_FLT_INSTANCE", "CallbackNodes", "field"),
        ("_FLT_INSTANCE", "FilterLink", "field"),
    ],
)

symbols_names = {mode: [t[0] if t[-1] == "symbol" else f"{t[0]}_{t[1]}" for t in symbols[mode]] for mode in modes}


def find(key: str, d: dict):
    for k, v in d.items():
        if k == key:
            return v
        if isinstance(v, dict):
            return find(key, v)
    return None


def printl(s, lock, **kwargs):
    with lock:
        print(s, **kwargs)


def downloadSpecificFile(entry, pe_basename, pe_ext, knownPEVersions, output_folder, lock):
    pe_name = f"{pe_basename}.{pe_ext}"

    if "fileInfo" not in entry:
        # printl(f'[!] Entry {pe_hash} has no fileInfo, skipping it.', lock)
        return "SKIP"
    if "timestamp" not in entry["fileInfo"]:
        # printl(f'[!] Entry has no timestamp, skipping it.', lock)
        return "SKIP"
    timestamp = entry["fileInfo"]["timestamp"]
    if "virtualSize" not in entry["fileInfo"]:
        # printl(f'[!] Entry has no virtualSize, skipping it.', lock)
        return "SKIP"
    if "machineType" not in entry["fileInfo"] or entry["fileInfo"]["machineType"] != machineType["x64"]:
        # printl('No machine Type', lock)
        return "SKIP"
    virtual_size = entry["fileInfo"]["virtualSize"]
    file_id = hex(timestamp).replace("0x", "").zfill(8).upper() + hex(virtual_size).replace("0x", "").upper()
    url = "https://msdl.microsoft.com/download/symbols/" + pe_name + "/" + file_id + "/" + pe_name
    try:
        version = entry["fileInfo"]["version"].split(" ")[0]
    except KeyError:
        version = find("version", entry).split(" ")[0]
        if version and version.count(".") != 3:
            version = None

    if not version:
        printl(f"[*] Error parsing version", lock)
        return "SKIP"

    # Output file format: <PE>_build-revision.<exe | dll>
    output_version = "-".join(version.split(".")[-2:])
    output_file = f"{pe_basename}_{output_version}.{pe_ext}"

    # If the PE version is already known, skip download.
    if output_file in knownPEVersions:
        printl(f"[*] Skipping download of known {pe_name} version: {output_file}", lock)
        return "SKIP"

    output_file_path = os.path.join(output_folder, output_file)
    if os.path.isfile(output_file_path):
        printl(f"[*] Skipping {output_file_path} which already exists", lock)
        return "SKIP"

    # printl(f'[*] Downloading {pe_name} version {version}... ', lock)
    try:
        peContent = get(url)
        if len(peContent.content) == 0:
            printl(f"[*] Skipping {output_file_path} which is empty on MS server", lock)
            return "SKIP"
        with open(output_file_path, "wb") as f:
            f.write(peContent.content)
        printl(
            f"[+] Finished download of {pe_name} version {version} (file: {output_file})!",
            lock,
        )
        return "OK"
    except Exception as e:
        printl(
            f"[!] ERROR : Could not download {pe_name} version {version} (URL: {url}): {str(e)}.",
            lock,
        )
        return "KO"


def downloadPEFileFromMS(pe_basename, pe_ext, knownPEVersions, output_folder):
    pe_name = f"{pe_basename}.{pe_ext}"

    print(f"[*] Downloading {pe_name} files!")

    pe_json_gz = get(f"https://winbindex.m417z.com/data/by_filename_compressed/{pe_name}.json.gz").content
    pe_json = decompress(pe_json_gz)
    pe_list = loads(pe_json)

    i = 0
    futures = set()
    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=THREADS_LIMIT) as executor:
        for pe_hash in pe_list:
            entry = pe_list[pe_hash]
            futures.add(
                executor.submit(
                    downloadSpecificFile,
                    entry,
                    pe_basename,
                    pe_ext,
                    knownPEVersions,
                    output_folder,
                    lock,
                )
            )
        for future in as_completed(futures):
            printl(f"{i + 1}/{len(pe_list)}", lock, end="\r")
            i += 1


def get_symbol_offset(symbols_info, symbol_name):
    for line in symbols_info:
        # sometimes, a "_" is prepended to the symbol name ...
        if line.strip().split(" ")[-1].endswith(symbol_name):
            return int(line.split(" ")[0], 16)
    else:
        return 0


def get_field_offset(symbols_info, field_name):
    for line in symbols_info:
        if field_name in line:
            assert "offset" in line
            symbol_offset = int(line.split("+")[-1], 16)
            return symbol_offset
    else:
        return 0


def get_file_version(path):
    pe = PE(path, fast_load=True)
    pe.parse_data_directories(directories=[DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    if not "VS_FIXEDFILEINFO" in pe.__dict__ or not pe.VS_FIXEDFILEINFO:
        raise RuntimeError("Version info not found in {pename}")
    verinfo = pe.VS_FIXEDFILEINFO[0]
    filever = (
        verinfo.FileVersionMS >> 16,
        verinfo.FileVersionMS & 0xFFFF,
        verinfo.FileVersionLS >> 16,
        verinfo.FileVersionLS & 0xFFFF,
    )
    return filever


# Takes a path to a PE file as argument, download the associated PDB
# Return the path of the existing PDB if any, and the content of the PDB in memory
# use keep_ondisk=False not to store the PDB files on disk
def get_pdb(pe: PE, pe_path, keep_ondisk=True, verbose=False):
    pdb_file_path = pe_path.rsplit(".", maxsplit=1)[0] + ".pdb"
    if not os.path.isfile(pdb_file_path):
        if verbose:
            print(f"[*] Downloading missing {pdb_file_path}")
        pe.parse_data_directories(directories=[DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]])
        guid_string = (
            f"{pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data1:08X}"
            + f"{pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data2:04X}"
            + f"{pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data3:04X}"
            + f"{pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data4:02X}"
            + f"{pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data5:02X}"
            + pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data6.hex().upper()
        )
        age_string = f"{pe.DIRECTORY_ENTRY_DEBUG[0].entry.Age:X}"
        pdb_filename = pe.DIRECTORY_ENTRY_DEBUG[0].entry.PdbFileName.decode().replace("\x00", "")
        pdb_url = f"https://msdl.microsoft.com/download/symbols/{pdb_filename}/{guid_string}{age_string}/{pdb_filename}"
        try:
            pdbContent = get(pdb_url)
            if len(pdbContent.content) == 0:
                raise ValueError("Downloaded PDB is empty")
            if keep_ondisk:
                with open(pdb_file_path, "wb") as f:
                    f.write(pdbContent.content)
                if verbose:
                    print(f"[+] Finished download PDB of {pe_path} version (file: {pdb_file_path})!")
                return pdb_file_path, pdbContent.content
            if not keep_ondisk:
                return None, pdbContent.content
        except Exception as e:
            print(f"[!] ERROR : Could not download PDB of {pe_path} (URL: {pdb_url}): {str(e)}.")
            return None, None
    elif os.path.isfile(pdb_file_path):
        pdb = Pdb(path=pdb_file_path)
        pe.parse_data_directories(directories=[DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]])
        guid_string = (
            f"{pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data1:08x}-"
            + f"{pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data2:04x}-"
            + f"{pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data3:04x}-"
            + f"{pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data4:02x}"
            + f"{pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data5:02x}-"
            + pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data6.hex().lower()
        )
        if str(pdb.PDBStream.Guid).lower() != guid_string:
            print(f"[!] ERROR : PDB {pdb_file_path} does match {pe_path}. Redownloading")
            del pdb
            os.remove(pdb_file_path)
            return get_pdb(pe, pe_path, keep_ondisk, verbose)
        return pdb_file_path, None


def extractOffsets(input_file, output_file, mode):
    if os.path.isfile(input_file):
        try:
            # check image type (ntoskrnl, wdigest, etc.)
            pe = PE(input_file, fast_load=True)
            export_directory_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
            export_directory_rva = export_directory_entry.VirtualAddress
            image_name_rva = pe.get_dword_at_rva(export_directory_rva + 3 * 4)
            name = pe.get_string_at_rva(image_name_rva).decode().lower()
            for image_name in supported_images:
                if image_name in name:
                    imageType = modes_by_imagename[image_name]
                    break
            else:
                print(f"[*] File {input_file} unrecognized")
                return

            # todo : remove this and make a unique function
            if mode != imageType:
                print(f"[*] Skipping {input_file} since we are in {mode} mode")
                return
            if os.path.sep not in input_file:
                input_file = "." + os.path.sep + input_file
            full_version = get_file_version(input_file)

            # Checks if the image version is already present in the CSV
            extension = extensions_by_mode[imageType]
            imageVersion = f"{imageType}_{full_version[2]}-{full_version[3]}.{extension}"

            if imageVersion in known_image_versions[imageType]:
                print(f"[*] Skipping known {imageType} version {imageVersion} (file: {input_file})")
                try:
                    """
                    Sometimes, PEs with different versions have the same exact code (only the version and the signature
                    change). They even have the same PE "timestamp" (which is a build hash in reality) and same virtual
                    size. So the download links on MS servers are the same. That's why winbindex sometimes shows the
                    metadata of one version of a PE, and the downloaded version is different.
                    Anyway, the offsets are identical between versions affected by these "collisions".
                    """
                    input_file_basename = os.path.basename(input_file)
                    if not input_file_basename.startswith(f"{imageType}_"):
                        return
                    if not input_file_basename.endswith(f".{extension}"):
                        return
                    if not input_file_basename.count("-") == 1:
                        return
                    version_2, version_3 = tuple(
                        int(part)
                        for part in input_file_basename[len(f"{imageType}_") : -len(f".{extension}")].split("-")
                    )
                    imageVersion = input_file_basename
                    if imageVersion in known_image_versions[imageType]:
                        return
                    print("\r", end="")  # Not skipping after all
                except ValueError:
                    return
                except KeyError:
                    return

            # print(f'[*] Processing {imageType} version {imageVersion} (file: {input_file})')
            # download the PDB if needed
            pdb_path, pdb_content = get_pdb(pe, input_file, verbose=True)

            pdb = Pdb(path=pdb_path, content=pdb_content)

            symbols_values = list()
            for *symbol_name, offset_type in symbols[imageType]:
                if offset_type == "symbol":
                    get_offset = pdb.get_symbol_offset
                elif offset_type == "field":
                    get_offset = pdb.get_field_offset
                else:
                    raise ValueError
                symbol_value = get_offset(*symbol_name)
                if symbol_value is None:
                    symbol_value = 0
                symbols_values.append(symbol_value)
                # print(f"[+] {symbol_name} = {hex(symbol_value)}")

            with CSVLock:
                with open(output_file, "a") as output:
                    output.write(f'{imageVersion},{",".join(hex(val).replace("0x","") for val in symbols_values)}\n')

            # print("wrote into CSV !")
            del pdb
            known_image_versions[imageType].append(imageVersion)
            print(f"[+] Finished processing of {imageType} {input_file}!")

        except PEFormatError as e:
            # file is not a PE
            if not input_file.endswith(".pdb"):
                print(f"[!] ERROR : Could not process file {input_file}: not a valid PE")
        except Exception as e:
            print(f"[!] ERROR : Could not process file {input_file}.")
            print(f"[!] Error message: {e}")
            raise e

    elif os.path.isdir(input_file):
        print(f"[*] Processing folder: {input_file}")
        with ThreadPoolExecutor(max_workers=THREADS_LIMIT) as extractorPool:
            args = [(os.path.join(input_file, file), output_file, mode) for file in os.listdir(input_file)]
            for i, res in enumerate(extractorPool.map(extractOffsets, *zip(*args))):
                print(f"{i + 1}/{len(args)}", end="\r")
        print(f"[+] Finished processing of folder {input_file}!")

    else:
        print(f"[!] ERROR : The specified input {input_file} is neither a file nor a directory.")


def loadOffsetsFromCSV(loadedVersions, CSVPath):
    print(f'[*] Loading the known known PE versions from "{CSVPath}".')

    with open(CSVPath, "r") as csvFile:
        csvReader = csv.reader(csvFile, delimiter=",")
        next(csvReader)
        for peLine in csvReader:
            loadedVersions.append(peLine[0])


def sortOutputFile(csvFile):
    def lineKey(line):
        major = int(line.split("_")[1].split("-")[0])
        minor = int(line.split("-")[1].split(".")[0])
        return (major, minor)

    with open(csvFile) as f:
        header_line = f.readline()
        content = f.readlines()
    with open(csvFile, "w") as f:
        f.write(header_line)
        f.writelines(sorted(set(content), key=lineKey))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    modes_str = "/".join(known_image_versions)
    files = " / ".join(modes_by_imagename)
    csvfiles = " / ".join(csvFilenameByMode.values())
    parser.add_argument(
        "mode",
        help=f"{modes_str}. Mode to download and extract offsets from either {files}",
    )
    parser.add_argument(
        "-i",
        "--input",
        dest="input",
        required=True,
        help=f"Single file or directory containing {files} to extract offsets from. If in download mode, the PE downloaded from MS symbols servers will be placed in this folder.",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        help=f"CSV file to write offsets to. If the specified file already exists, only new ntoskrnl versions will be downloaded / analyzed. Defaults to {csvfiles} in the current folder.",
    )
    parser.add_argument(
        "-d",
        "--download",
        dest="download",
        action="store_true",
        help="Flag to download the PE from Microsoft servers using list of versions from winbindex.m417z.com.",
    )

    args = parser.parse_args()
    mode = args.mode.lower()
    if mode not in known_image_versions:
        print(f'[!] ERROR : unsupported mode "{args.mode}", supported mode are: {modes}')
        exit(1)

    # If the output file exists, load the already analyzed image versions.
    # Otherwise, write CSV headers to the new file.
    if not args.output:
        args.output = csvFilenameByMode[mode]
    if os.path.isfile(args.output):
        loadOffsetsFromCSV(known_image_versions[mode], args.output)
        print(f'[+] Loaded {len(known_image_versions[mode])} known {mode} versions from "{args.output}"')
    else:
        with open(args.output, "w") as output:
            output.write(mode + "Version," + ",".join(elem for elem in symbols_names[mode]) + "\n")

    # In download mode, an updated list of image versions published will be retrieved from https://winbindex.m417z.com.
    # The symbols for each version will be downloaded from the Microsoft symbols servers.
    # Only new versions will be downloaded if the specified output file already contains offsets.
    if args.download:
        if not os.path.isdir(args.input):
            print("[!] ERROR : in download mode, -i / --input option must specify a folder")
            exit(1)
        extension = extensions_by_mode[mode]
        downloadPEFileFromMS(mode, extension, known_image_versions[mode], args.input)

    # Extract the offsets from the specified file or the folders containing image files.
    extractOffsets(args.input, args.output, mode)

    sortOutputFile(args.output)
