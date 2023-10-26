import os
import glob
from pathlib import Path
import r2pipe

def SettingDirectory(dir: str):
    # 定位資料集以及專案位置

    # Datasets Directory
    Datasets_dir = Path(dir)

    # Create Directories
    List_Folder_Datasets = ['Image', 'Sample', 'Asm_r2', 'Asm_objdump', 'Library', 'Section_Attributions', 'CSV', 'NPZ', 'JOBLIB', 'TXT', 'Reports'] 

    for Folder in List_Folder_Datasets:
        if not Path(Datasets_dir).joinpath(Folder).exists():
            Path(Datasets_dir).joinpath(Folder).mkdir()
        else :
            num_files = len(os.listdir(Path(Datasets_dir).joinpath(Folder)))
        globals()[Folder + "_dir"] = Path(Datasets_dir).joinpath(Folder)
        print('%-20s'%Folder, "Folder exists:", '[%-3s]'%("yes") if (Path(Datasets_dir).joinpath(Folder).exists()) else "no", "[", '%8s'%num_files, "files conteneted]")


    # File ID Lists
    # 創建檔案列表,紀錄檔案名稱

    List_ids = list()
    List_files = list()
    Dict_id2file = dict()
    Dict_file2id = dict()
    
    for filelist in Path(Datasets_dir).joinpath("Sample").glob("*"):
        List_ids.append(filelist.name.split('.',)[0])
        List_files.append(filelist.name)
        Dict_file2id[filelist.name] = filelist.name.split('.',)[0]
        Dict_id2file[filelist.name.split('.',)[0]] = filelist.name
    return List_ids, List_files, Dict_file2id, Dict_id2file


# Main
home_path = "E:\\Malware\\R2_disassemble\\Files\\"
Sample_dir = home_path + "Samples\\"
Asm_r2_dir = home_path + "Asm_r2\\"
List_ids, List_files, Dict_file2id, Dict_id2file = SettingDirectory(home_path)

for i in Path(Sample_dir).glob("*?*"):
    filename = os.path.basename(i)
    r = r2pipe.open(str(i))
    r.cmd('e asm.bytes = true')     # Set Create Bytes to True
    r.cmd('e asm.nbytes = 20')      # Set Bytes Length
    r.cmd('aaaa')
    r.cmd('iS')
    r.cmd('afl')
    assembly_code_section = r.cmd('afl').splitlines(True)
    
    with open(f'{Asm_r2_dir}\\{filename}.asm', mode = "w+", newline = '', encoding = "utf-8") as file_write:
        for j in assembly_code_section:
            section_address = j.split(' ',2)[0]
            r.cmd(section_address)
            assembly_code = r.cmd('pdr')
            file_write.write(assembly_code)