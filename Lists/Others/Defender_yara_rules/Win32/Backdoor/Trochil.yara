rule Backdoor_Win32_Trochil_A_2147708431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Trochil.A.dll!dha"
        threat_id = "2147708431"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Trochil"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "computer.security-centers.com" ascii //weight: 1
        $x_1_2 = "%ALLUSERSPROFILE%\\WEventsCache" ascii //weight: 1
        $x_1_3 = "WMICache information from Windows Management file" ascii //weight: 1
        $x_1_4 = "WMICacheEvents Modules Service" ascii //weight: 1
        $x_1_5 = "%s [%s:%d] %u" ascii //weight: 1
        $x_1_6 = "\\destruction\\SelfDestruction.cpp" ascii //weight: 1
        $x_1_7 = "add to send msg failed" ascii //weight: 1
        $x_1_8 = "create exitevent failed." ascii //weight: 1
        $x_1_9 = "create parameters key failed %u" ascii //weight: 1
        $x_1_10 = "create socket failed E%u" ascii //weight: 1
        $x_1_11 = "create target file[%s] for adjust time failed." ascii //weight: 1
        $x_1_12 = "decrypt dll file" ascii //weight: 1
        $x_1_13 = "deinit servant" ascii //weight: 1
        $x_1_14 = "deinit servantshell" ascii //weight: 1
        $x_1_15 = "DeinitServant" ascii //weight: 1
        $x_1_16 = "get address of p[%s] failed" ascii //weight: 1
        $x_1_17 = "get ip for[%s] failed. WE%d" ascii //weight: 1
        $x_1_18 = "Get targetdir times failed[%s]." ascii //weight: 1
        $x_1_19 = "Getipaddrtable failed. E%u" ascii //weight: 1
        $x_1_20 = "init servant manager failed" ascii //weight: 1
        $x_1_21 = "init servant. server : %s:%d" ascii //weight: 1
        $x_1_22 = "init servantshell. filepath is %s%s" ascii //weight: 1
        $x_1_23 = "InitServant" ascii //weight: 1
        $x_1_24 = "invalid time for [%s][%u][%u][%u]" ascii //weight: 1
        $x_1_25 = "load memlibrary failed [%s]" ascii //weight: 1
        $x_1_26 = "load servant failed" ascii //weight: 1
        $x_1_27 = "load servantcore success" ascii //weight: 1
        $x_1_28 = "no handler for [%I64u]" ascii //weight: 1
        $x_1_29 = "open service reg key failed %u" ascii //weight: 1
        $x_1_30 = "open target[%s] failed." ascii //weight: 1
        $x_1_31 = "pcreate socket failed." ascii //weight: 1
        $x_1_32 = "protocol : %s[%d]" ascii //weight: 1
        $x_1_33 = "recv msgid[%I64u]. try to handle it" ascii //weight: 1
        $x_1_34 = "send and recv[%d] failed" ascii //weight: 1
        $x_1_35 = "sendrecv msg [%d] failed" ascii //weight: 1
        $x_1_36 = "SET DEFAULT COMM : %u" ascii //weight: 1
        $x_1_37 = "set servicedll failed 1. %u" ascii //weight: 1
        $x_1_38 = "set servicedll failed 2. %u" ascii //weight: 1
        $x_1_39 = "SetFileTime[%s] failed." ascii //weight: 1
        $x_1_40 = "socket is invalid. connect failed" ascii //weight: 1
        $x_1_41 = "socket is invalid. send failed" ascii //weight: 1
        $x_1_42 = "socket is open. please close it first." ascii //weight: 1
        $x_1_43 = "SvtShell.cpp" ascii //weight: 1
        $x_1_44 = "try to clean %s" ascii //weight: 1
        $x_1_45 = "try to remove[%s]" ascii //weight: 1
        $x_1_46 = "XLServant" ascii //weight: 1
        $n_10_47 = "C:\\dev\\Paladin\\Paladin\\target\\release\\deps\\Paladin.pdb" ascii //weight: -10
        $n_10_48 = "C:\\Program Files\\Paladin\\Logs\\Log.paladin" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (5 of ($x*))
}

rule Backdoor_Win32_Trochil_A_2147708432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Trochil.A!!Trochil.A.dll!dha"
        threat_id = "2147708432"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Trochil"
        severity = "Critical"
        info = "Trochil: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        info = "dll: Dynamic Link Library component of a malware"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "computer.security-centers.com" ascii //weight: 1
        $x_1_2 = "%ALLUSERSPROFILE%\\WEventsCache" ascii //weight: 1
        $x_1_3 = "WMICache information from Windows Management file" ascii //weight: 1
        $x_1_4 = "WMICacheEvents Modules Service" ascii //weight: 1
        $x_1_5 = "%s [%s:%d] %u" ascii //weight: 1
        $x_1_6 = "\\destruction\\SelfDestruction.cpp" ascii //weight: 1
        $x_1_7 = "add to send msg failed" ascii //weight: 1
        $x_1_8 = "create exitevent failed." ascii //weight: 1
        $x_1_9 = "create parameters key failed %u" ascii //weight: 1
        $x_1_10 = "create socket failed E%u" ascii //weight: 1
        $x_1_11 = "create target file[%s] for adjust time failed." ascii //weight: 1
        $x_1_12 = "decrypt dll file" ascii //weight: 1
        $x_1_13 = "deinit servant" ascii //weight: 1
        $x_1_14 = "deinit servantshell" ascii //weight: 1
        $x_1_15 = "DeinitServant" ascii //weight: 1
        $x_1_16 = "get address of p[%s] failed" ascii //weight: 1
        $x_1_17 = "get ip for[%s] failed. WE%d" ascii //weight: 1
        $x_1_18 = "Get targetdir times failed[%s]." ascii //weight: 1
        $x_1_19 = "Getipaddrtable failed. E%u" ascii //weight: 1
        $x_1_20 = "init servant manager failed" ascii //weight: 1
        $x_1_21 = "init servant. server : %s:%d" ascii //weight: 1
        $x_1_22 = "init servantshell. filepath is %s%s" ascii //weight: 1
        $x_1_23 = "InitServant" ascii //weight: 1
        $x_1_24 = "invalid time for [%s][%u][%u][%u]" ascii //weight: 1
        $x_1_25 = "load memlibrary failed [%s]" ascii //weight: 1
        $x_1_26 = "load servant failed" ascii //weight: 1
        $x_1_27 = "load servantcore success" ascii //weight: 1
        $x_1_28 = "no handler for [%I64u]" ascii //weight: 1
        $x_1_29 = "open service reg key failed %u" ascii //weight: 1
        $x_1_30 = "open target[%s] failed." ascii //weight: 1
        $x_1_31 = "pcreate socket failed." ascii //weight: 1
        $x_1_32 = "protocol : %s[%d]" ascii //weight: 1
        $x_1_33 = "recv msgid[%I64u]. try to handle it" ascii //weight: 1
        $x_1_34 = "send and recv[%d] failed" ascii //weight: 1
        $x_1_35 = "sendrecv msg [%d] failed" ascii //weight: 1
        $x_1_36 = "SET DEFAULT COMM : %u" ascii //weight: 1
        $x_1_37 = "set servicedll failed 1. %u" ascii //weight: 1
        $x_1_38 = "set servicedll failed 2. %u" ascii //weight: 1
        $x_1_39 = "SetFileTime[%s] failed." ascii //weight: 1
        $x_1_40 = "socket is invalid. connect failed" ascii //weight: 1
        $x_1_41 = "socket is invalid. send failed" ascii //weight: 1
        $x_1_42 = "socket is open. please close it first." ascii //weight: 1
        $x_1_43 = "SvtShell.cpp" ascii //weight: 1
        $x_1_44 = "try to clean %s" ascii //weight: 1
        $x_1_45 = "try to remove[%s]" ascii //weight: 1
        $x_1_46 = "XLServant" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Trochil_D_2147708665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Trochil.D.dll!dha"
        threat_id = "2147708665"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Trochil"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Microsoft\\Internet Explorer\\runas.exe" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\Internet Explorer\\mon" ascii //weight: 1
        $x_1_3 = "\\Microsoft\\Internet Explorer\\notepad.exe" ascii //weight: 1
        $x_1_4 = "\\Microsoft\\Internet Explorer\\nvsvc.exe" ascii //weight: 1
        $x_1_5 = "\\Microsoft\\Internet Explorer\\SBieDll.dll" ascii //weight: 1
        $x_1_6 = "\\Microsoft\\Internet Explorer\\maindll.dll" ascii //weight: 1
        $x_1_7 = "\\Microsoft\\Internet Explorer\\conhost.exe" ascii //weight: 1
        $x_1_8 = "%s[%d-%d-%d %d:%d:%d]" ascii //weight: 1
        $x_1_9 = "%s\\%d-%02d-%02d.sys" ascii //weight: 1
        $x_1_10 = "KB923561" ascii //weight: 1
        $x_1_11 = "srvlic.dll" ascii //weight: 1
        $x_1_12 = "update.lnk" ascii //weight: 1
        $x_2_13 = "dll2.xor" ascii //weight: 2
        $x_1_14 = "move \"%s\" \"%s%s\"" ascii //weight: 1
        $x_1_15 = "copy \"%s%s\" \"%s%s\\%s\"" ascii //weight: 1
        $x_1_16 = "move \"%s%s\" \"%s%s\"" ascii //weight: 1
        $x_1_17 = {00 75 70 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_2_18 = {00 74 68 69 73 20 69 73 20 55 50 30 30 37 00}  //weight: 2, accuracy: High
        $x_2_19 = {00 61 64 6d 69 6e 7c 7c 30 39 30 32 00}  //weight: 2, accuracy: High
        $x_1_20 = {00 4d 65 73 73 61 67 65 4c 6f 6f 70 00}  //weight: 1, accuracy: High
        $x_1_21 = {00 49 4e 53 00 44 45 4c 00 48 4f 4d 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

