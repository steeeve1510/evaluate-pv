
import pandas as pd
import os

def read_df(folder, reader, folder_path):
    all_files = os.listdir(folder_path + '/' + folder)
    files = filter(lambda f: not f.startswith('.'), all_files)
    absolute_files = map(lambda f: folder_path + '/' + folder + '/' + f, files)
    return pd.concat(map(reader, absolute_files))

def read_pv(file):
    _df = pd.read_csv(file, date_format='%d.%m.%Y, %H:%M:%S', index_col ="Timestamp")
    return _df['Energy in Wm (MRAM)'] / 60 / 1000

def read_sm(file):
    _df = pd.read_csv(file)
    _df.columns = ['energy', 'from', 'to', 'quality']
    _df['timestamp'] = pd.to_datetime(_df['to'])
    _df['timestamp'] = _df['timestamp'].dt.tz_convert('Europe/Vienna')
    _df['timestamp'] = _df['timestamp'].dt.tz_localize(None)
    _df = _df.set_index('timestamp')
    return _df['energy'] / 1000