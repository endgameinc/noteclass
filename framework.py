import os
import time
import pickle
import psutil
import multiprocessing

import wmi
import win32api
import spacy
import pandas as pd

from sklearn.feature_extraction.stop_words import ENGLISH_STOP_WORDS as stopwords

pd.set_option('chained_assignment', None)
spacy_tok = spacy.load('en')
vect = pickle.load(open("vect.p", "rb"))
nb = pickle.load(open("nb.p", "rb"))

def clean_text(doc):
    d = doc.replace('\n', ' ').replace('\r', '').replace('_', '').lower()
    d = d.replace('\x00', '')
    sent = []
    t = spacy_tok(d)
    
    for token in t:
        if (token.is_alpha and not token.is_stop and token.text not in stopwords and token.text in spacy_tok.vocab and len(token.text) > 2):
            sent.append(token.lemma_)

    return ' '.join(sent)

def read_file(file):
    t = None

    try:
        f = open(file, 'r', encoding="ISO-8859-1")    
        t = f.read()
        f.close()
    except:
        pass
        
    return t

def model_predict(doc, file_path = None):
    panda_series = pd.Series({0:doc})
    X_test_vect = vect.transform(panda_series)
    res = nb.predict(X_test_vect)[0]
    return(res)

def model_result(file_path):
    result = 2
    t = read_file(file_path)
    
    if (t is None):
        return result
    
    statinfo = os.stat(file_path)
    
    if (statinfo.st_size < 20000):
        doc = clean_text(t)
        if (doc.count(' ') >= 4):
            if (len(set(doc.split(' '))) >= 4):
                result = model_predict(doc, file_path)
                
    return result

#========================
    
def worker(wq):
    process_whitelist = []

    while (True):
        entry = wq.get()
        file_path = entry[0]
        process_id = entry[1]
        process_name = entry[2]
        record_number = entry[3]

        if ((process_id, process_name) in process_whitelist):
            continue

        result = model_result(file_path)
        
        if (1 == result):
            #does process ID exist?
        
            if (psutil.pid_exists(int(process_id))):
                process = psutil.Process(int(process_id))
                basename_1 = os.path.basename(process.name()).lower()
                basename_2 = os.path.basename(process_name).lower()
                #does this process have the same name?
                
                if (basename_1 == basename_2):
                    try:
                        process.suspend()
                        print("Process suspended: " + repr(process_id))
                        alert_str = "The following file was classified as a ransom note:\n{}\nThe following process has been suspended:\n{} | (PID: {})\n\nClick OK to TERMINATE the process\nClick Cancel to resume and whitelist the process".format(file_path,process_name,process_id)
                        feedback = win32api.MessageBox(0, alert_str, "Ransomware Detected", 0x00001031)

                        if (feedback == 2):
                            process.resume()
                            print("Process resumed: " + repr(process_id))
                            #whitelisting will prevent further txt files from being classified for this process
                            process_whitelist.append((process_id, process_name))
                        else:
                            process.terminate()
                            print("Process terminated: " + repr(process_id))
                            
                    except:
                        pass
                        
#========================

if __name__ == '__main__':                    
    work_queue = multiprocessing.Queue()        
    mp = multiprocessing.Process(target=worker, args=(work_queue,))
    mp.start()
            
    first_pass = True
    record_number = 0
    max_record_number = 0
    entry_cache = []
    c = wmi.WMI()
    
    base_query = "SELECT * FROM Win32_NTLogEvent WHERE LogFile = 'Microsoft-Windows-Sysmon/Operational' AND EventCode = 11 AND RecordNumber > {}"
    
    while (True):
        wql = base_query.format(max_record_number)
        events = c.query(wql)
        
        for event in events:
            record_number = event.RecordNumber
            process_id = event.InsertionStrings[3]
            process_name = event.InsertionStrings[4]
            file_path = event.InsertionStrings[5]
            entry = (file_path, process_id, process_name, record_number)
            
            if (entry not in entry_cache) and (not first_pass):
                work_queue.put(entry)
                entry_cache.append(entry)

            if (record_number > max_record_number):
                max_record_number = record_number
                
        if (first_pass):
            first_pass = False
                
        time.sleep(.1)
        entry_cache = []
        