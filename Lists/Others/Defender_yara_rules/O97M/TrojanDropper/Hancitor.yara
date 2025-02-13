rule TrojanDropper_O97M_Hancitor_AJ_2147769990_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.AJ!MTB"
        threat_id = "2147769990"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub gotodown()" ascii //weight: 1
        $x_1_2 = "Call gototwo" ascii //weight: 1
        $x_1_3 = "If Dir(pafh & \"\\W0rd.dll\") = \"\" Then" ascii //weight: 1
        $x_1_4 = "If Dir(ActiveDocument.AttachedTemplate.Path & \"\\W0rd.dll\") = \"\" Then" ascii //weight: 1
        $x_1_5 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_6 = "For Each vhhs In fld.SUBFOLDERS" ascii //weight: 1
        $x_1_7 = "Call checkthe(afs)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_AJS_2147770438_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.AJS!MTB"
        threat_id = "2147770438"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "& \"\\W0rd.dll\") = \"\" Then" ascii //weight: 1
        $x_1_2 = {53 75 62 20 67 6f 74 6f 64 6f 77 6e 28 29 02 00 43 61 6c 6c 20 67 6f 74 6f 74 77 6f}  //weight: 1, accuracy: Low
        $x_1_3 = "& \"\\ya.wav\" As ActiveDocument.AttachedTemplate.Path & \"\\W0rd.dll\"" ascii //weight: 1
        $x_1_4 = "If Dir(Left(ActiveDocument.AttachedTemplate.Path, ntgs) & \"Loc\" & \"al\\Te\" & \"mp\", vbDirectory) = \"\" Then" ascii //weight: 1
        $x_1_5 = "& pushstr & \"ll,DllUnregisterServer\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAN_2147771280_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAN!MTB"
        threat_id = "2147771280"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_2 = "& \"\\W0rd.dll\") = \"\" Then" ascii //weight: 1
        $x_1_3 = "& \"\\ya.wav\" As ActiveDocument.AttachedTemplate.Path & \"\\\" & \"W0rd.dll\"" ascii //weight: 1
        $x_1_4 = "& \"\\ya.wav\" As fu" ascii //weight: 1
        $x_1_5 = "DllUnregisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAN_2147771280_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAN!MTB"
        threat_id = "2147771280"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_3 = {73 74 72 46 69 6c 65 45 78 69 73 74 73 20 3d 20 44 69 72 28 52 6f 6f 74 50 61 74 68 20 26 20 22 5c [0-8] 2e 74 6d 70 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "If strFileExists = \"\" Then" ascii //weight: 1
        $x_1_5 = "Function chek()" ascii //weight: 1
        $x_1_6 = "Dim jsa As String" ascii //weight: 1
        $x_1_7 = {53 75 62 20 67 6f 74 6f 64 6f 77 6e 28 29 02 00 43 61 6c 6c 20 70 6f 6c 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAB_2147771385_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAB!MTB"
        threat_id = "2147771385"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "asdf = RootPath" ascii //weight: 1
        $x_1_2 = "& \"\\W0rd.dll\") = \"\" Then" ascii //weight: 1
        $x_1_3 = {53 65 74 20 66 73 6f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-8] 20 26 20 22 70 22 20 26 20 22 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 22 20 26 20 22 4f 62 6a 65 63 74 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_5 = "strFileExists = Dir(RootPath & \"\\ya.wav\")" ascii //weight: 1
        $x_1_6 = "For Each vhhs In fld.SUBFOLDERS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAC_2147771386_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAC!MTB"
        threat_id = "2147771386"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub gotodown()" ascii //weight: 1
        $x_1_2 = "Call gototwo" ascii //weight: 1
        $x_1_3 = {73 74 72 46 69 6c 65 45 78 69 73 74 73 20 3d 20 44 69 72 28 [0-8] 20 26 20 22 5c 79 61 2e 77 61 76 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "If Dir(nothings & \"\\\" & \"W0rd.dll\") = \"\" Then" ascii //weight: 1
        $x_1_5 = "& \"\\ya.wav\" As ActiveDocument.AttachedTemplate.Path & \"\\\" & \"W0rd.dll\"" ascii //weight: 1
        $x_1_6 = "If strFileExists = \"\" Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAD_2147771387_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAD!MTB"
        threat_id = "2147771387"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call gotodown" ascii //weight: 1
        $x_1_2 = "W0rd.dll" ascii //weight: 1
        $x_1_3 = "ya.wav" ascii //weight: 1
        $x_1_4 = "If Dir(Left(ActiveDocument.AttachedTemplate.Path, ntgs) & \"Loc\" & \"al\\Te\" & \"mp\", vbDirectory) = \"\" Then" ascii //weight: 1
        $x_1_5 = "Call Getme(Left(ActiveDocument.AttachedTemplate.Path, ntgs) & \"Local\\Temp\")" ascii //weight: 1
        $x_1_6 = "Selection.TypeBackspace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAE_2147771388_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAE!MTB"
        threat_id = "2147771388"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "glog = ActiveDocument.AttachedTemplate.Path" ascii //weight: 1
        $x_1_2 = "Dim fu As String" ascii //weight: 1
        $x_1_3 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_4 = "fu = glog & \"\\W0rd.dll\"" ascii //weight: 1
        $x_1_5 = {4e 61 6d 65 20 6d 79 68 6f 6d 65 20 26 20 22 5c 79 61 2e 77 61 76 22 20 41 73 20 66 75 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_6 = "Call regsrva.ShellExecute(fa, yy, \" \", SW_SHOWNORMAL)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAF_2147771389_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAF!MTB"
        threat_id = "2147771389"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ya.wav" ascii //weight: 1
        $x_1_2 = "pushstr = \"\\W\" & \"0rd.d\"" ascii //weight: 1
        $x_1_3 = "fa = fps & \"u\" & jsd & \"ll\" & hh" ascii //weight: 1
        $x_1_4 = "Dim regsrva As New Shell32.Shell" ascii //weight: 1
        $x_1_5 = "& pushstr & \"ll\" & \",\" & \"Dll\" & \"UnregisterServer\"" ascii //weight: 1
        $x_1_6 = "Call regsrva.ShellExecute(fa, yy, \" \", SW_SHOWNORMAL)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAG_2147771390_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAG!MTB"
        threat_id = "2147771390"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "& jsd &" ascii //weight: 1
        $x_1_2 = "& \"Dll\" & \"UnregisterServer\"" ascii //weight: 1
        $x_1_3 = "asdf = RootPath" ascii //weight: 1
        $x_1_4 = "ya.wav" ascii //weight: 1
        $x_1_5 = "W0rd.dll" ascii //weight: 1
        $x_1_6 = "& \"\\ya.wav\" As fu" ascii //weight: 1
        $x_1_7 = "Call gotodown" ascii //weight: 1
        $x_1_8 = "Sub gotodown()" ascii //weight: 1
        $x_1_9 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_10 = {46 6f 72 20 45 61 63 68 20 [0-6] 20 49 6e 20 66 6c 64 2e 53 55 42 46 4f 4c 44 45 52 53}  //weight: 1, accuracy: Low
        $x_1_11 = "& \"\\ya.wav\" As ActiveDocument.AttachedTemplate.Path & \"\\\" & \"W0rd.dll\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAH_2147772432_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAH!MTB"
        threat_id = "2147772432"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "If Dir(nothings & \"\\\" & \"W0rd.dll\") = \"\" Then" ascii //weight: 1
        $x_1_2 = {4e 61 6d 65 20 73 66 20 26 20 22 5c [0-8] 2e 74 6d 70 22 20 41 73 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 22 5c 22 20 26 20 22 57 30 72 64 2e 64 6c 6c 22}  //weight: 1, accuracy: Low
        $x_1_3 = "yy = glops & yy & pushstr & \"ll\" & \",\" & \"Dll\" & \"UnregisterServer\"" ascii //weight: 1
        $x_1_4 = "fa = fps & \"u\" & jsd & \"ll\" & hh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAI_2147772469_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAI!MTB"
        threat_id = "2147772469"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = "& jsd &" ascii //weight: 1
        $x_1_3 = "& \"Dll\" & \"UnregisterServer\"" ascii //weight: 1
        $x_1_4 = "Dim pifpaf As String" ascii //weight: 1
        $x_1_5 = {53 75 62 20 67 6f 74 6f 64 6f 77 6e 28 29 02 00 43 61 6c 6c 20 67 6f 74 6f 74 77 6f}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 74 6d 70 22 20 41 73 20 66 75 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_7 = {43 61 6c 6c 20 73 73 73 73 02 00 44 69 6d 20 70 75 73 68 73 74 72 20 41 73 20 53 74 72 69 6e 67}  //weight: 1, accuracy: Low
        $x_1_8 = "Call regsrva.ShellExecute(fa," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAJ_2147772520_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAJ!MTB"
        threat_id = "2147772520"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_3 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_4 = "If Dir(Left(ActiveDocument.AttachedTemplate.Path, ntgs) & \"Loc\" & \"al\\Te\" & \"mp\", vbDirectory) = \"\" Then" ascii //weight: 1
        $x_1_5 = {43 61 6c 6c 20 47 65 74 6d 65 28 4c 65 66 74 28 [0-6] 2c 20 6e 74 67 73 29 20 26 20 22 4c 6f 63 22 20 26 20 22 61 6c 5c 54 65 22 20 26 20 22 6d 70 22 29}  //weight: 1, accuracy: Low
        $x_1_6 = "As ActiveDocument.AttachedTemplate.Path & \"\\\" & \"W0rd.dll\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAK_2147772570_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAK!MTB"
        threat_id = "2147772570"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = "Dim jsa As String" ascii //weight: 1
        $x_1_3 = "mp\" As ActiveDocument.AttachedTemplate.Path & \"\\\" & \"W0rd.dll\"" ascii //weight: 1
        $x_1_4 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_5 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_6 = {73 74 72 46 69 6c 65 45 78 69 73 74 73 20 3d 20 44 69 72 28 52 6f 6f 74 50 61 74 68 20 26 20 22 5c [0-8] 2e 74 6d 70 22 29}  //weight: 1, accuracy: Low
        $x_1_7 = {53 75 62 20 67 6f 74 6f 64 6f 77 6e 28 29 02 00 43 61 6c 6c 20 67 6f 74 6f 74 77 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAL_2147772571_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAL!MTB"
        threat_id = "2147772571"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = "& jsd &" ascii //weight: 1
        $x_1_3 = {44 69 6d 20 66 75 20 41 73 20 53 74 72 69 6e 67 02 00 66 75 20 3d 20 67 6c 6f 67 20 26 20 22 5c 57 30 72 64 2e 64 6c 6c 22 02 00 4e 61 6d 65 20 6d 79 68 6f 6d 65 20 26 20 22 5c [0-8] 2e 74 6d 70 22 20 41 73 20 66 75 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = {43 61 6c 6c 20 73 73 73 73 02 00 44 69 6d 20 70 75 73 68 73 74 72 20 41 73 20 53 74 72 69 6e 67}  //weight: 1, accuracy: Low
        $x_1_5 = {53 75 62 20 67 6f 74 6f 64 6f 77 6e 28 29 02 00 43 61 6c 6c 20 67 6f 74 6f 74 77 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAM_2147772796_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAM!MTB"
        threat_id = "2147772796"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = {26 20 70 75 73 68 73 74 72 20 26 20 22 6c 6c 22 20 26 20 22 2c 22 20 26 20 22 44 6c 6c 22 20 26 20 [0-16] 20 26 20 22 72 65 67 69 73 74 65 72 53 65 72 76 65 72 22}  //weight: 1, accuracy: Low
        $x_1_3 = {43 61 6c 6c 20 72 65 67 73 72 76 61 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 [0-21] 2c 20 22 20 22 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 29}  //weight: 1, accuracy: Low
        $x_1_4 = "Dim regsrva As New Shell32.Shell" ascii //weight: 1
        $x_1_5 = {53 75 62 20 67 6f 74 6f 64 6f 77 6e 28 29 02 00 43 61 6c 6c 20 67 6f 74 6f 74 77 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAO_2147772910_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAO!MTB"
        threat_id = "2147772910"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = "& jsd &" ascii //weight: 1
        $x_1_3 = "If Dir(nothings & \"\\\" & \"W0rd.dll\") = \"\" Then" ascii //weight: 1
        $x_1_4 = "& \"mp\" As ActiveDocument.AttachedTemplate.Path & \"\\\" & \"W0rd.dll\"" ascii //weight: 1
        $x_1_5 = {53 75 62 20 73 73 73 73 28 29 02 00 44 69 6d 20 70 6f 73 6c 20 41 73 20 53 74 72 69 6e 67}  //weight: 1, accuracy: Low
        $x_1_6 = "Call gotodown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAP_2147772911_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAP!MTB"
        threat_id = "2147772911"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = "& jsd &" ascii //weight: 1
        $x_1_3 = "Call gotodown" ascii //weight: 1
        $x_1_4 = {2e 74 6d 70 22 20 41 73 20 66 75 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = "Dim regsrva As New Shell32.Shell" ascii //weight: 1
        $x_1_6 = "& yy & pushstr & \"ll\" & \",\" & \"UninstallFont" ascii //weight: 1
        $x_1_7 = {43 61 6c 6c 20 72 65 67 73 72 76 61 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 66 61 2c 20 79 79 2c 20 22 20 22 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 29 02 00 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAQ_2147772942_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAQ!MTB"
        threat_id = "2147772942"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = "& jsd &" ascii //weight: 1
        $x_1_3 = "Call ssss" ascii //weight: 1
        $x_1_4 = "Dim regsrva As New Shell32.Shell" ascii //weight: 1
        $x_1_5 = "& yy & pushstr & \"ll\" & \",\" & \"UninstallFont\"" ascii //weight: 1
        $x_1_6 = "Call regsrva.ShellExecute(fa, yy, \" \", SW_SHOWNORMAL)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAR_2147773006_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAR!MTB"
        threat_id = "2147773006"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = {44 69 6d 20 66 73 6f 20 41 73 20 4f 62 6a 65 63 74 02 00 44 69 6d 20 66 6c 64 20 41 73 20 4f 62 6a 65 63 74 02 00 44 69 6d 20 76 68 68 73 20 41 73 20 4f 62 6a 65 63 74 02 00 44 69 6d 20 61 66 73 20 41 73 20 53 74 72 69 6e 67}  //weight: 1, accuracy: Low
        $x_1_3 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_4 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_5 = {73 74 72 46 69 6c 65 45 78 69 73 74 73 20 3d 20 44 69 72 28 52 6f 6f 74 50 61 74 68 20 26 20 22 5c [0-16] 2e 74 6d 70 22 29}  //weight: 1, accuracy: Low
        $x_1_6 = {53 65 74 20 66 6c 64 20 3d 20 4e 6f 74 68 69 6e 67 02 00 53 65 74 20 66 73 6f 20 3d 20 4e 6f 74 68 69 6e 67}  //weight: 1, accuracy: Low
        $x_1_7 = "& \"W0rd.dll\") = \"\" Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAS_2147773007_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAS!MTB"
        threat_id = "2147773007"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = "Sub gotodown()" ascii //weight: 1
        $x_1_3 = "Sub ssss()" ascii //weight: 1
        $x_1_4 = "& jsd & \"ll\" & hh" ascii //weight: 1
        $x_1_5 = {43 61 6c 6c 20 73 73 73 73 02 00 44 69 6d 20 70 75 73 68 73 74 72 20 41 73 20 53 74 72 69 6e 67 02 00 70 75 73 68 73 74 72 20 3d 20 22 5c 57}  //weight: 1, accuracy: Low
        $x_1_6 = "& yy & pushstr & \"l" ascii //weight: 1
        $x_1_7 = "Call regsrva.ShellExecute(fa, yy, \" \", SW_SHOWNORMAL)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAT_2147773320_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAT!MTB"
        threat_id = "2147773320"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = "asdf = RootPath" ascii //weight: 1
        $x_1_3 = "Dim fer As String" ascii //weight: 1
        $x_1_4 = "Dim jsa As String" ascii //weight: 1
        $x_1_5 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_6 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_7 = {73 74 72 46 69 6c 65 45 78 69 73 74 73 20 3d 20 44 69 72 28 52 6f 6f 74 50 61 74 68 20 26 20 22 5c [0-16] 2e 74 22 20 26 20 22 6d 70 22 29}  //weight: 1, accuracy: Low
        $x_1_8 = "If strFileExists = \"\" Then" ascii //weight: 1
        $x_1_9 = "For Each vhhs In fld.SUBFOLDERS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAU_2147773321_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAU!MTB"
        threat_id = "2147773321"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = "Sub gotodown()" ascii //weight: 1
        $x_1_3 = "Call hhhss" ascii //weight: 1
        $x_1_4 = "& \"m\" & \"p\" As ActiveDocument.Application.StartupPath & \"\\\" & \"W0rd.dll\"" ascii //weight: 1
        $x_1_5 = {72 65 70 69 64 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_6 = "strFileExists = Dir(sf &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAV_2147773322_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAV!MTB"
        threat_id = "2147773322"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = "Sub hi(myhome As String)" ascii //weight: 1
        $x_1_3 = "Dim glog As String" ascii //weight: 1
        $x_1_4 = "glog = repid" ascii //weight: 1
        $x_1_5 = "Dim hsa As String" ascii //weight: 1
        $x_1_6 = "hsa = glog & \"\\W0rd.dll\"" ascii //weight: 1
        $x_1_7 = "Call jop(myhome, hsa)" ascii //weight: 1
        $x_1_8 = "Sub jop(uuu As String, aaaa As String)" ascii //weight: 1
        $x_1_9 = "Call rnee(uuu, aaaa)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAW_2147773613_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAW!MTB"
        threat_id = "2147773613"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = "asdf = RootPath" ascii //weight: 1
        $x_1_3 = "Dim fer As String" ascii //weight: 1
        $x_1_4 = "Function chek()" ascii //weight: 1
        $x_1_5 = "Dim jsa As String" ascii //weight: 1
        $x_1_6 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_7 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_8 = "& \"W0rd.dll\") = \"\" Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAX_2147773614_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAX!MTB"
        threat_id = "2147773614"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = "& jsd &" ascii //weight: 1
        $x_1_3 = "Sub gotodown()" ascii //weight: 1
        $x_1_4 = "Sub hhhhh()" ascii //weight: 1
        $x_1_5 = "Dim posl As String" ascii //weight: 1
        $x_1_6 = "Call jop(myhome, hsa)" ascii //weight: 1
        $x_1_7 = "As ActiveDocument.Application.StartupPath & \"\\\" & \"W0rd.dll\"" ascii //weight: 1
        $x_1_8 = {26 20 70 75 73 68 73 74 72 20 26 20 22 6c 6c 22 20 26 20 [0-8] 20 26 20 22 73 74 61 6c 6c 46 6f 6e 74 22}  //weight: 1, accuracy: Low
        $x_1_9 = "Call regsrva.ShellExecute(fa, yy, \" \", SW_SHOWNORMAL)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_HAZ_2147773682_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.HAZ!MTB"
        threat_id = "2147773682"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = "& jsd &" ascii //weight: 1
        $x_1_3 = "Function chek()" ascii //weight: 1
        $x_1_4 = "Dim jsa As String" ascii //weight: 1
        $x_1_5 = "Sub hhhhh()" ascii //weight: 1
        $x_1_6 = "Dim posl As String" ascii //weight: 1
        $x_1_7 = "As ActiveDocument.Application.StartupPath & \"\\\" & \"W0rd.dll\"" ascii //weight: 1
        $x_1_8 = "& pushstr & \"ll\" &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAA_2147773722_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAA!MTB"
        threat_id = "2147773722"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = "& jsd &" ascii //weight: 1
        $x_1_3 = "jsa = repid" ascii //weight: 1
        $x_1_4 = ".tm\" & \"p\"" ascii //weight: 1
        $x_1_5 = "asdf = RootPath" ascii //weight: 1
        $x_1_6 = "Dim fer As String" ascii //weight: 1
        $x_1_7 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_8 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_9 = "& \"W0\" & \"rd.dll\") = \"\" Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAB_2147773723_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAB!MTB"
        threat_id = "2147773723"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "W0rd.dll" ascii //weight: 1
        $x_1_2 = "Call regsrva.ShellExecute(fa, yy, \" \", SW_SHOWNORMAL)" ascii //weight: 1
        $x_1_3 = "Dim regsrva As New Shell32.Shell" ascii //weight: 1
        $x_1_4 = "Call hhhhh" ascii //weight: 1
        $x_1_5 = "Dim pushstr As String" ascii //weight: 1
        $x_1_6 = "Call stetptwwo" ascii //weight: 1
        $x_1_7 = "fa = fps & \"u\" & jsd & \"ll\" & hh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAC_2147773788_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAC!MTB"
        threat_id = "2147773788"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nothings = pafh & \"\\\" & \"W0\" & \"rd.dll\"" ascii //weight: 1
        $x_1_2 = ".t\" & \"m\" & \"p\" As ActiveDocument.Application.StartupPath & \"\\\" & \"W0\" & \"rd.dll\"" ascii //weight: 1
        $x_1_3 = "& jsd & \"ll\" &" ascii //weight: 1
        $x_1_4 = "jsa = repid" ascii //weight: 1
        $x_1_5 = "Sub hhhhh()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAD_2147773804_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAD!MTB"
        threat_id = "2147773804"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub hi(myhome As String)" ascii //weight: 1
        $x_1_2 = "Dim glog As String" ascii //weight: 1
        $x_1_3 = "glog = repid" ascii //weight: 1
        $x_1_4 = "Dim hsa As String" ascii //weight: 1
        $x_1_5 = "hsa = glog" ascii //weight: 1
        $x_1_6 = "Dim jsd As String" ascii //weight: 1
        $x_1_7 = "Dim pushstr As String" ascii //weight: 1
        $x_1_8 = {43 61 6c 6c 20 6a 6f 70 28 6d 79 68 6f 6d 65 2c 20 68 73 61 20 26 20 22 5c 57 30 22 20 26 20 22 72 64 2e 64 6c 6c 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAE_2147773805_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAE!MTB"
        threat_id = "2147773805"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rd.dll" ascii //weight: 1
        $x_1_2 = "Call hhhhh" ascii //weight: 1
        $x_1_3 = "Dim pushstr As String" ascii //weight: 1
        $x_1_4 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_5 = "Dim regsrva As New Shell32.Shell" ascii //weight: 1
        $x_1_6 = "yy = glops & yy & pushstr & \"ll\" & gpsa & \"stallFont\"" ascii //weight: 1
        $x_1_7 = "Call regsrva.ShellExecute(fa, yy, \" \", SW_SHOWNORMAL)" ascii //weight: 1
        $x_1_8 = "fa = fps & \"u\" & jsd & \"ll\" & hh" ascii //weight: 1
        $x_1_9 = "Call stetptwwo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAF_2147773855_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAF!MTB"
        threat_id = "2147773855"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \"\\\" & \"W0\" & \"rd.dll\") = \"\" Then" ascii //weight: 1
        $x_1_2 = "Call hhhhh" ascii //weight: 1
        $x_1_3 = "Dim pushstr As String" ascii //weight: 1
        $x_1_4 = "pushstr = \"\\W\" & \"0r\" & \"d.d" ascii //weight: 1
        $x_1_5 = "Dim jsd As String" ascii //weight: 1
        $x_1_6 = "Call regsrva.ShellExecute(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_PVY_2147774012_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.PVY!MTB"
        threat_id = "2147774012"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If Dir(jsa & \"\\\" & \"W0\" & \"rd.d\" & \"ll\") = \"\" Then" ascii //weight: 1
        $x_1_2 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_3 = "jsa = repid" ascii //weight: 1
        $x_1_4 = "Call rnee(uuu, aaaa)" ascii //weight: 1
        $x_1_5 = "Sub hhhhh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_PVZ_2147774013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.PVZ!MTB"
        threat_id = "2147774013"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub hi(myhome As String" ascii //weight: 1
        $x_1_2 = "Dim glog As String" ascii //weight: 1
        $x_1_3 = "glog = repid" ascii //weight: 1
        $x_1_4 = "Dim hsa As String" ascii //weight: 1
        $x_1_5 = "hsa = glog" ascii //weight: 1
        $x_1_6 = {43 61 6c 6c 20 6a 6f 70 28 6d 79 68 6f 6d 65 2c 20 68 73 61 20 26 20 22 5c 57 30 22 20 26 20 22 72 64 2e 64 22 20 26 20 22 6c 6c 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAG_2147774167_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAG!MTB"
        threat_id = "2147774167"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".t\" & \"m\" & \"p\" As Word.ActiveDocument.AttachedTemplate.Path & \"\\\" & \"W0\" & \"rd.d\" & \"ll\"" ascii //weight: 1
        $x_1_2 = "Sub jop(uuu As String, aaaa As String)" ascii //weight: 1
        $x_1_3 = "Call rnee(uuu, aaaa)" ascii //weight: 1
        $x_1_4 = "Call nm(ololow)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAH_2147774168_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAH!MTB"
        threat_id = "2147774168"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fa = fps & \"u\" & jsd & \"ll\" & hh" ascii //weight: 1
        $x_1_2 = "Dim regsrva As New Shell32.Shell" ascii //weight: 1
        $x_1_3 = "& yy & pushstr & \"ll\" & \",UminslaIIF0mt\"" ascii //weight: 1
        $x_1_4 = "Call regsrva.ShellExecute(fa, yy, \" \", SW_SHOWNORMAL)" ascii //weight: 1
        $x_1_5 = "Call hhhhh" ascii //weight: 1
        $x_1_6 = "Dim pushstr As String" ascii //weight: 1
        $x_1_7 = "pushstr = \"\\W\" & \"0r\" & \"d.d\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAI_2147774216_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAI!MTB"
        threat_id = "2147774216"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \"\\\" & \"W0\" & \"rd.d\" & \"ll\") = \"\" Then" ascii //weight: 1
        $x_1_2 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_3 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_4 = "Dim uuj As String" ascii //weight: 1
        $x_1_5 = "Function chek()" ascii //weight: 1
        $x_1_6 = "Dim jsa As String" ascii //weight: 1
        $x_1_7 = "jsa = Word.ActiveDocument.AttachedTemplate.Path" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAJ_2147774217_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAJ!MTB"
        threat_id = "2147774217"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "W0\" & \"rd.d\" & \"ll" ascii //weight: 1
        $x_1_2 = "Sub hhhhh()" ascii //weight: 1
        $x_1_3 = "Dim posl As String" ascii //weight: 1
        $x_1_4 = "posl = Word.ActiveDocument.AttachedTemplate.Path" ascii //weight: 1
        $x_1_5 = "Dim ntgs" ascii //weight: 1
        $x_1_6 = "Dim sda" ascii //weight: 1
        $x_1_7 = "Call fke" ascii //weight: 1
        $x_1_8 = "yer = \"Loc\" & \"al\" & \"\\Te\" & \"mp\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAK_2147774218_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAK!MTB"
        threat_id = "2147774218"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub hi(myhome As String)" ascii //weight: 1
        $x_1_2 = "Dim glog As String" ascii //weight: 1
        $x_1_3 = "glog = Word.ActiveDocument.AttachedTemplate.Path" ascii //weight: 1
        $x_1_4 = "Dim hsa As String" ascii //weight: 1
        $x_1_5 = "hsa = glog" ascii //weight: 1
        $x_1_6 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_7 = {43 61 6c 6c 20 6a 6f 70 28 6d 79 68 6f 6d 65 2c 20 68 73 61 20 26 20 22 5c 57 30 22 20 26 20 22 72 64 2e 64 22 20 26 20 22 6c 6c 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAL_2147774219_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAL!MTB"
        threat_id = "2147774219"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Dim ololow As String" ascii //weight: 1
        $x_1_2 = "ololow = sf" ascii //weight: 1
        $x_1_3 = "Dim nothings As String" ascii //weight: 1
        $x_1_4 = "nothings = pafh & \"\\\" & \"W0\" & \"rd.d\" & \"ll\"" ascii //weight: 1
        $x_1_5 = {49 66 20 44 69 72 28 73 66 20 26 20 22 5c [0-16] 2e 74 22 20 26 20 22 6d 70 22 29 20 3d 20 22 22 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_6 = "Sub checkthe(sf As String)" ascii //weight: 1
        $x_1_7 = "Call nm(ololow)" ascii //weight: 1
        $x_1_8 = "& jsd &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAM_2147774220_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAM!MTB"
        threat_id = "2147774220"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call stetptwwo" ascii //weight: 1
        $x_1_2 = "Call hhhhh" ascii //weight: 1
        $x_1_3 = "Dim pushstr As String" ascii //weight: 1
        $x_1_4 = "pushstr = \"\\W\" & \"0r\" & \"d.d\"" ascii //weight: 1
        $x_1_5 = "fa = fps & \"u\" & jsd & \"ll\" & hh" ascii //weight: 1
        $x_1_6 = "Dim regsrva As New Shell32.Shell" ascii //weight: 1
        $x_1_7 = "& yy & pushstr & \"ll\" &" ascii //weight: 1
        $x_1_8 = "Call regsrva.ShellExecute(fa, yy, \" \", SW_SHOWNORMAL)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAN_2147774280_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAN!MTB"
        threat_id = "2147774280"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "If Dir(jsa & \"\\\" & \"W0\" & \"rd.d\" & \"l\" & \"l\") = \"\" Then" ascii //weight: 1
        $x_1_2 = "Dim fer As String" ascii //weight: 1
        $x_1_3 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_4 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_5 = "Dim uuj As String" ascii //weight: 1
        $x_1_6 = {75 75 6a 20 3d 20 22 5c 22 20 26 20 22 [0-16] 2e 74 22 20 26 20 22 6d 70 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAO_2147774281_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAO!MTB"
        threat_id = "2147774281"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub hi(myhome As String)" ascii //weight: 1
        $x_1_2 = "Dim glog As String" ascii //weight: 1
        $x_1_3 = "glog = Word.ActiveDocument.AttachedTemplate.Path" ascii //weight: 1
        $x_1_4 = "Dim hsa As String" ascii //weight: 1
        $x_1_5 = "hsa = glog" ascii //weight: 1
        $x_1_6 = {43 61 6c 6c 20 6a 6f 70 28 6d 79 68 6f 6d 65 2c 20 68 73 61 20 26 20 22 5c 57 30 22 20 26 20 22 72 64 2e 64 22 20 26 20 22 6c 22 20 26 20 22 6c 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAP_2147774282_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAP!MTB"
        threat_id = "2147774282"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".t\" & \"m\" & \"p\" As Word.ActiveDocument.AttachedTemplate.Path & \"\\\" & \"W0\" & \"rd.d\" & \"l\" & \"l\"" ascii //weight: 1
        $x_1_2 = "Sub jop(uuu As String, aaaa As String)" ascii //weight: 1
        $x_1_3 = "Call rnee(uuu, aaaa)" ascii //weight: 1
        $x_1_4 = "Sub checkthe(sf As String)" ascii //weight: 1
        $x_1_5 = "& jsd &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAQ_2147774283_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAQ!MTB"
        threat_id = "2147774283"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call hhhhh" ascii //weight: 1
        $x_1_2 = "W0\" & \"rd.d\" & \"l\" & \"l\"" ascii //weight: 1
        $x_1_3 = "fa = fps & \"u\" & jsd & \"ll\" & hh" ascii //weight: 1
        $x_1_4 = "Dim pushstr As String" ascii //weight: 1
        $x_1_5 = "Dim regsrva As New Shell32.Shell" ascii //weight: 1
        $x_1_6 = "yy = glops & yy & pushstr &" ascii //weight: 1
        $x_1_7 = "Call regsrva.ShellExecute(fa, yy, \" \", SW_SHOWNORMAL)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAR_2147775283_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAR!MTB"
        threat_id = "2147775283"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "jsa & \"\\\" & \"W0\" & \"r\" & \"d.d" ascii //weight: 1
        $x_1_2 = "Dim fer As String" ascii //weight: 1
        $x_1_3 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_4 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_5 = "Dim uuj As String" ascii //weight: 1
        $x_1_6 = {75 75 6a 20 3d 20 22 5c 22 20 26 20 22 [0-18] 2e 74 30 22 20 26 20 22 6d 70 22}  //weight: 1, accuracy: Low
        $x_1_7 = "strFileExists = Dir(RootPath & uuj)" ascii //weight: 1
        $x_1_8 = "Call checkthe(afs)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAS_2147775284_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAS!MTB"
        threat_id = "2147775284"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "W0\" & \"r\" & \"d.d\" & \"l\" & \"l" ascii //weight: 1
        $x_1_2 = "Sub hhhhh()" ascii //weight: 1
        $x_1_3 = "Dim posl As String" ascii //weight: 1
        $x_1_4 = "Call fke" ascii //weight: 1
        $x_1_5 = "jos = posl" ascii //weight: 1
        $x_1_6 = "Call Getme(Left(klas, ntgs) & yer)" ascii //weight: 1
        $x_1_7 = "Dim jos As String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAT_2147775285_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAT!MTB"
        threat_id = "2147775285"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub hi(myhome As String)" ascii //weight: 1
        $x_1_2 = "Dim glog As String" ascii //weight: 1
        $x_1_3 = "glog = Word.ActiveDocument.AttachedTemplate.Path" ascii //weight: 1
        $x_1_4 = "Dim hsa As String" ascii //weight: 1
        $x_1_5 = "hsa = glog" ascii //weight: 1
        $x_1_6 = "Function iep()" ascii //weight: 1
        $x_1_7 = {43 61 6c 6c 20 6a 6f 70 28 6d 79 68 6f 6d 65 2c 20 68 73 61 20 26 20 22 5c 57 30 22 20 26 20 22 72 22 20 26 20 22 64 2e 64 22 20 26 20 22 6c 22 20 26 20 22 6c 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAU_2147775286_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAU!MTB"
        threat_id = "2147775286"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \"m\" & \"p\" As Word.ActiveDocument.AttachedTemplate.Path & \"\\\" & \"W0\" & \"r\" & \"d.d\" & \"l\" & \"l\"" ascii //weight: 1
        $x_1_2 = "Sub jop(uuu As String, aaaa As String)" ascii //weight: 1
        $x_1_3 = "Call nm(ololow)" ascii //weight: 1
        $x_1_4 = "Call rnee(uuu, aaaa)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAV_2147775287_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAV!MTB"
        threat_id = "2147775287"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "W\" & \"0\" & \"r\" & \"d.d" ascii //weight: 1
        $x_1_2 = "Call hhhhh" ascii //weight: 1
        $x_1_3 = "glops = Word.ActiveDocument.AttachedTemplate.Path" ascii //weight: 1
        $x_1_4 = "Dim pus As String" ascii //weight: 1
        $x_1_5 = "fa = fps & \"u\" & jsd & \"ll\" & hh" ascii //weight: 1
        $x_1_6 = "Dim regsrva As New Shell32.Shell" ascii //weight: 1
        $x_1_7 = "Call regsrva.ShellExecute(fa, yy, \" \", SW_SHOWNORMAL)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAW_2147775411_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAW!MTB"
        threat_id = "2147775411"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "W0\" & \"r\" & \"d.d\" & \"l\" & \"l" ascii //weight: 1
        $x_1_2 = "asdf = RootPath" ascii //weight: 1
        $x_1_3 = "Dim fer As String" ascii //weight: 1
        $x_1_4 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_5 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_6 = "Dim uuj As String" ascii //weight: 1
        $x_1_7 = "strFileExists = Dir(RootPath & uuj)" ascii //weight: 1
        $x_1_8 = "Call checkthe(afs)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAX_2147775630_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAX!MTB"
        threat_id = "2147775630"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "W\" & \"0\" & \"r\" & \"d.d" ascii //weight: 1
        $x_1_2 = ".d\" & \"l\" & \"l" ascii //weight: 1
        $x_1_3 = "& jsd & \"ll\" & hh" ascii //weight: 1
        $x_1_4 = "Call stetptwwo" ascii //weight: 1
        $x_1_5 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_6 = "Word.ActiveDocument.AttachedTemplate.Path" ascii //weight: 1
        $x_1_7 = "Dim jsa As String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAY_2147775963_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAY!MTB"
        threat_id = "2147775963"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Static.dll" ascii //weight: 1
        $x_1_2 = "asdf = RootPath" ascii //weight: 1
        $x_1_3 = "Dim fer As String" ascii //weight: 1
        $x_1_4 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_5 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_6 = "Dim uuj As String" ascii //weight: 1
        $x_1_7 = {75 75 6a 20 3d 20 22 5c [0-18] 2e 74 30 22 20 26 20 22 6d 70 22}  //weight: 1, accuracy: Low
        $x_1_8 = "strFileExists = Dir(RootPath & uuj)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_IAZ_2147775964_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.IAZ!MTB"
        threat_id = "2147775964"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \"m\" & \"p\" As Word.ActiveDocument.AttachedTemplate.Path & \"\\Static.dll\"" ascii //weight: 1
        $x_1_2 = "posl = Word.ActiveDocument.AttachedTemplate.Path" ascii //weight: 1
        $x_1_3 = "Call Getme(Left(klas, ntgs) & yer)" ascii //weight: 1
        $x_1_4 = "Sub hhhhh()" ascii //weight: 1
        $x_1_5 = "Dim posl As String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAA_2147775965_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAA!MTB"
        threat_id = "2147775965"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub hi(myhome As String)" ascii //weight: 1
        $x_1_2 = "Dim glog As String" ascii //weight: 1
        $x_1_3 = "Dim pafh As String" ascii //weight: 1
        $x_1_4 = "pafh = iep" ascii //weight: 1
        $x_1_5 = "glog = pafh" ascii //weight: 1
        $x_1_6 = {43 61 6c 6c 20 6a 6f 70 28 6d 79 68 6f 6d 65 2c 20 67 6c 6f 67 20 26 20 22 5c 53 74 61 74 69 63 2e 64 6c 6c 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAB_2147775966_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAB!MTB"
        threat_id = "2147775966"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Static.d" ascii //weight: 1
        $x_1_2 = "Call hhhhh" ascii //weight: 1
        $x_1_3 = "Call stetptwwo" ascii //weight: 1
        $x_1_4 = "fa = fps & \"u\" & jsd & \"ll\" & hh" ascii //weight: 1
        $x_1_5 = "Dim regsrva As New Shell32.Shell" ascii //weight: 1
        $x_1_6 = "Call regsrva.ShellExecute(fa, yy, \" \", SW_SHOWNORMAL)" ascii //weight: 1
        $x_1_7 = "glops = Word.ActiveDocument.AttachedTemplate.Path" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAC_2147776075_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAC!MTB"
        threat_id = "2147776075"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \"m\" & \"p\" As Word.ActiveDocument.Application.StartupPath & \"\\Static.dll" ascii //weight: 1
        $x_1_2 = "posl = Word.ActiveDocument.Application.StartupPath" ascii //weight: 1
        $x_1_3 = "Sub hhhhh()" ascii //weight: 1
        $x_1_4 = "Dim posl As String" ascii //weight: 1
        $x_1_5 = "Call cvbc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAD_2147776076_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAD!MTB"
        threat_id = "2147776076"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Static.dll" ascii //weight: 1
        $x_1_2 = "Sub checkthe(sf As String)" ascii //weight: 1
        $x_1_3 = {49 66 20 44 69 72 28 73 66 20 26 20 22 5c [0-18] 2e 74 30 22 20 26 20 22 6d 70 22 29 20 3d 20 22 22 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_4 = "pafh = iep" ascii //weight: 1
        $x_1_5 = "Call nm(ololow)" ascii //weight: 1
        $x_1_6 = "ololow = sf" ascii //weight: 1
        $x_1_7 = "Sub jop(uuu As String, aaaa As String)" ascii //weight: 1
        $x_1_8 = "Call rnee(uuu, aaaa)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAE_2147776077_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAE!MTB"
        threat_id = "2147776077"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"\\Static.d" ascii //weight: 1
        $x_1_2 = "Call stetptwwo" ascii //weight: 1
        $x_1_3 = "Call hhhhh" ascii //weight: 1
        $x_1_4 = "glops = Word.ActiveDocument.Application.StartupPath" ascii //weight: 1
        $x_1_5 = "Dim pus As String" ascii //weight: 1
        $x_1_6 = "& jsd & \"ll\" & hh" ascii //weight: 1
        $x_1_7 = "Dim regsrva As New Shell32.Shell" ascii //weight: 1
        $x_1_8 = "Call regsrva.ShellExecute(fa, yy, \" \", SW_SHOWNORMAL)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAF_2147776308_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAF!MTB"
        threat_id = "2147776308"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \"m\" & \"p\" As Options.DefaultFilePath(wdTempFilePath) & \"\\Static.dll" ascii //weight: 1
        $x_1_2 = "Sub hhhhh()" ascii //weight: 1
        $x_1_3 = "jos = posl" ascii //weight: 1
        $x_1_4 = "Dim posl As String" ascii //weight: 1
        $x_1_5 = "ololow As String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAG_2147776309_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAG!MTB"
        threat_id = "2147776309"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub hi(myhome As String)" ascii //weight: 1
        $x_1_2 = "Dim plop As String" ascii //weight: 1
        $x_1_3 = "Dim pafh As String" ascii //weight: 1
        $x_1_4 = "pafh = iep" ascii //weight: 1
        $x_1_5 = "plop = pafh" ascii //weight: 1
        $x_1_6 = {43 61 6c 6c 20 6a 6f 70 28 6d 79 68 6f 6d 65 2c 20 70 6c 6f 70 20 26 20 22 5c 53 74 61 74 69 63 2e 64 6c 6c 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAH_2147776310_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAH!MTB"
        threat_id = "2147776310"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Static.dll" ascii //weight: 1
        $x_1_2 = "Sub checkthe(sf As String)" ascii //weight: 1
        $x_1_3 = "Dim pafh As String" ascii //weight: 1
        $x_1_4 = "pafh = iep" ascii //weight: 1
        $x_1_5 = "Dim oass As String" ascii //weight: 1
        $x_1_6 = "oass = \"m\" & \"p\"" ascii //weight: 1
        $x_1_7 = "Dim ololow As String" ascii //weight: 1
        $x_1_8 = "ololow = sf" ascii //weight: 1
        $x_1_9 = "Sub jop(uuu As String, aaaa As String)" ascii //weight: 1
        $x_1_10 = "Call nm(ololow)" ascii //weight: 1
        $x_1_11 = "Call rnee(uuu, aaaa)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAI_2147776311_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAI!MTB"
        threat_id = "2147776311"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"\\Static.d\"" ascii //weight: 1
        $x_1_2 = "Call stetptwwo" ascii //weight: 1
        $x_1_3 = "Call hhhhh" ascii //weight: 1
        $x_1_4 = "fa = fps & \"u\" & jsd & \"ll\" & hh" ascii //weight: 1
        $x_1_5 = "Call regsrva.ShellExecute(fa, yy, \" \", SW_SHOWNORMAL)" ascii //weight: 1
        $x_1_6 = "Dim regsrva As New Shell32.Shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAJ_2147776512_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAJ!MTB"
        threat_id = "2147776512"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "As Options.DefaultFilePath(wdTempFilePath) & \"\\Static.dll\"" ascii //weight: 1
        $x_1_2 = "Sub hhhhh()" ascii //weight: 1
        $x_1_3 = "Dim posl As String" ascii //weight: 1
        $x_1_4 = "If Dir(Left(jos, ntgs) & yer, vbDirectory) = \"\" Then" ascii //weight: 1
        $x_1_5 = "Call Getme(Left(klas, ntgs) & yer)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAK_2147776513_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAK!MTB"
        threat_id = "2147776513"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Static.dll" ascii //weight: 1
        $x_1_2 = "Sub rnee(myhome As String, hsa As String)" ascii //weight: 1
        $x_1_3 = {4e 61 6d 65 20 6d 79 68 6f 6d 65 20 26 20 22 5c [0-16] 2e 70 75 6d 70 6c 22 20 41 73 20 68 73 61 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = "Function fuxk()" ascii //weight: 1
        $x_1_5 = {66 75 78 6b 20 3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 54 61 62 6c 65 73 28 31 29 2e 43 65 6c 6c 28 31 2c 20 31 29 2e 52 61 6e 67 65 2e 54 65 78 74 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAL_2147776514_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAL!MTB"
        threat_id = "2147776514"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Function chek()" ascii //weight: 1
        $x_1_2 = "Dim jos As String" ascii //weight: 1
        $x_1_3 = "jos = Options.DefaultFilePath(wdTempFilePath)" ascii //weight: 1
        $x_1_4 = "If Dir(jos & \"\\Static.dll\") = \"\" Then" ascii //weight: 1
        $x_1_5 = "chek = 0" ascii //weight: 1
        $x_1_6 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_7 = "Call checkthe(afs)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAM_2147776618_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAM!MTB"
        threat_id = "2147776618"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Static.dll" ascii //weight: 1
        $x_1_2 = "Selection.MoveDown Unit:=wdLine, Count:=1" ascii //weight: 1
        $x_1_3 = "Call stetptwwo" ascii //weight: 1
        $x_1_4 = "Call hhhhh" ascii //weight: 1
        $x_1_5 = "& jsd &" ascii //weight: 1
        $x_1_6 = "Dim regsrva As New Shell32.Shell" ascii //weight: 1
        $x_1_7 = "Call regsrva.ShellExecute(fa, yy, \" \", SW_SHOWNORMAL)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAN_2147776619_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAN!MTB"
        threat_id = "2147776619"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Static.dll" ascii //weight: 1
        $x_1_2 = "Call stetptwwo" ascii //weight: 1
        $x_1_3 = "Call hhhhh" ascii //weight: 1
        $x_1_4 = "& jsd &" ascii //weight: 1
        $x_1_5 = "Dim regsrva As New Shell32.Shell" ascii //weight: 1
        $x_1_6 = "Dim geto As String" ascii //weight: 1
        $x_1_7 = "Dim pus As String" ascii //weight: 1
        $x_1_8 = "Call nm(ololow)" ascii //weight: 1
        $x_1_9 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAO_2147777421_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAO!MTB"
        threat_id = "2147777421"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Static.d\" & \"l\" & \"l\"" ascii //weight: 1
        $x_1_2 = "Sub rnee(myhome As String, hsa As String)" ascii //weight: 1
        $x_1_3 = {4e 61 6d 65 20 6d 79 68 6f 6d 65 20 26 20 22 5c 6d 73 61 6c 73 2e 70 75 6d 70 6c 22 20 41 73 20 68 73 61 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = "Function fuxk()" ascii //weight: 1
        $x_1_5 = {66 75 78 6b 20 3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 54 61 62 6c 65 73 28 31 29 2e 43 65 6c 6c 28 31 2c 20 31 29 2e 52 61 6e 67 65 2e 54 65 78 74 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAP_2147777422_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAP!MTB"
        threat_id = "2147777422"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub stetptwwo()" ascii //weight: 1
        $x_1_2 = "Call hhhhh" ascii //weight: 1
        $x_1_3 = "= \"\\Static.d\"" ascii //weight: 1
        $x_1_4 = "& jsd & \"l\" & \"l\" &" ascii //weight: 1
        $x_1_5 = {76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 02 00 45 6e 64 20 49 66 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAQ_2147777931_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAQ!MTB"
        threat_id = "2147777931"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub hi(myhome As String)" ascii //weight: 1
        $x_1_2 = "Dim plop As String" ascii //weight: 1
        $x_1_3 = "Dim pafh As String" ascii //weight: 1
        $x_1_4 = "Sub hhhhh()" ascii //weight: 1
        $x_1_5 = "pafh = iep" ascii //weight: 1
        $x_1_6 = "plop = pafh" ascii //weight: 1
        $x_1_7 = "Call jop(myhome, plop & \"\\\" & \"Static.d\" & \"l\" & \"l\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAR_2147777932_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAR!MTB"
        threat_id = "2147777932"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Static.d\" & \"l\" & \"l" ascii //weight: 1
        $x_1_2 = "& jsd &" ascii //weight: 1
        $x_1_3 = "Call nm(ololow)" ascii //weight: 1
        $x_1_4 = "Call rnee(uuu, aaaa)" ascii //weight: 1
        $x_1_5 = "Sub jop(uuu As String, aaaa As String)" ascii //weight: 1
        $x_1_6 = ".pumpl\") = \"\" Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAS_2147777933_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAS!MTB"
        threat_id = "2147777933"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"\\Static.d" ascii //weight: 1
        $x_1_2 = "Call hhhhh" ascii //weight: 1
        $x_1_3 = "Dim pus As String" ascii //weight: 1
        $x_1_4 = "Call stetptwwo" ascii //weight: 1
        $x_1_5 = "& jsd &" ascii //weight: 1
        $x_1_6 = {76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 02 00 45 6e 64 20 49 66 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAT_2147778102_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAT!MTB"
        threat_id = "2147778102"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".pumpl\" As pafh & \"\\\" & \"Static.d\" & \"l\" & \"l\"" ascii //weight: 1
        $x_1_2 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_3 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_4 = "For Each vhhs In fld.SUBFOLDERS" ascii //weight: 1
        $x_1_5 = "(ololow As String" ascii //weight: 1
        $x_1_6 = "Dim jos As String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAU_2147778339_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAU!MTB"
        threat_id = "2147778339"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Application.Run(\"jop\", myhome, plop & \"\\\" & \"Sta\" & \"tic.d\" & \"l\" & \"l\")" ascii //weight: 1
        $x_1_2 = "Sub hi(myhome As String)" ascii //weight: 1
        $x_1_3 = "Dim plop As String" ascii //weight: 1
        $x_1_4 = "Dim pafh As String" ascii //weight: 1
        $x_1_5 = "Sub hhhhh()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAV_2147778340_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAV!MTB"
        threat_id = "2147778340"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sta\" & \"tic.d\" & \"l\" & \"l" ascii //weight: 1
        $x_1_2 = ".pumpl\") = \"\" Then" ascii //weight: 1
        $x_1_3 = "Call nm(ololow)" ascii //weight: 1
        $x_1_4 = "Call rnee(uuu, aaaa)" ascii //weight: 1
        $x_1_5 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_6 = "Sub rnee(myhome As String, hsa As String)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAW_2147778341_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAW!MTB"
        threat_id = "2147778341"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"\\Sta\" & \"tic.d" ascii //weight: 1
        $x_1_2 = "Call stetptwwo" ascii //weight: 1
        $x_1_3 = "Call hhhhh" ascii //weight: 1
        $x_1_4 = "Dim pus As String" ascii //weight: 1
        $x_1_5 = "Dim pafh As String" ascii //weight: 1
        $x_1_6 = "& jsd & \"l\" &" ascii //weight: 1
        $x_1_7 = {76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 02 00 45 6e 64 20 49 66 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAX_2147778657_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAX!MTB"
        threat_id = "2147778657"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \"S\" & \"ta\" & \"tic.d\" & \"l\" & \"l\") = \"\" Then" ascii //weight: 1
        $x_1_2 = "= Application.Run(\"hi\", RootPath)" ascii //weight: 1
        $x_1_3 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_4 = "fld.SUBFOLDERS" ascii //weight: 1
        $x_1_5 = "asdf = RootPath" ascii //weight: 1
        $x_1_6 = "ololow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAY_2147778658_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAY!MTB"
        threat_id = "2147778658"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Application.Run(\"jop\", myhome, plop & \"\\\" & \"S\" & \"ta\" & \"tic.d\" & \"l\" & \"l\")" ascii //weight: 1
        $x_1_2 = "Sub hhhhh()" ascii //weight: 1
        $x_1_3 = "Dim posl As String" ascii //weight: 1
        $x_1_4 = "Dim pafh As String" ascii //weight: 1
        $x_1_5 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_6 = "ololow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JAZ_2147778659_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JAZ!MTB"
        threat_id = "2147778659"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "S\" & \"ta\" & \"tic.d\" & \"l\" & \"l" ascii //weight: 1
        $x_1_2 = "= Application.Run(\"nm\", ololow)" ascii //weight: 1
        $x_1_3 = "Sub jop(uuu As String, aaaa As String)" ascii //weight: 1
        $x_1_4 = "Call rnee(uuu, aaaa)" ascii //weight: 1
        $x_1_5 = ".pumpl\") = \"\" Then" ascii //weight: 1
        $x_1_6 = "= ThisDocument.Tables(1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_KAA_2147778660_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.KAA!MTB"
        threat_id = "2147778660"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"\\\" & \"S\" & \"ta\" & \"tic.d\"" ascii //weight: 1
        $x_1_2 = "Call stetptwwo" ascii //weight: 1
        $x_1_3 = "Call hhhhh" ascii //weight: 1
        $x_1_4 = "Dim pafh As String" ascii //weight: 1
        $x_1_5 = "Dim pus As String" ascii //weight: 1
        $x_1_6 = "& jsd &" ascii //weight: 1
        $x_1_7 = {76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 02 00 45 6e 64 20 49 66 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_RVA_2147779042_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.RVA!MTB"
        threat_id = "2147779042"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_2 = "Name ololow & \"\\ms\" & \"als.pumpl\" As pafh & \"\\MsMp.dll\"" ascii //weight: 1
        $x_1_3 = "\"\\ms\" & \"als.pumpl\"" ascii //weight: 1
        $x_1_4 = "Application.Run(\"jop\", myhome, plop & \"\\MsMp.dll\")" ascii //weight: 1
        $x_1_5 = "Call rnee(uuu, aaaa)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EMLU_2147779234_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EMLU!MTB"
        threat_id = "2147779234"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \"\\MsMp.dll\") = \"\" Then" ascii //weight: 1
        $x_1_2 = "Set fld = fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_3 = "plop & \"\\MsMp.dll\")" ascii //weight: 1
        $x_1_4 = "Call rnee(uuu, aaaa)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_DR_2147779374_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.DR!MTB"
        threat_id = "2147779374"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uuj = \"\\plumbus.rik\"" ascii //weight: 1
        $x_1_2 = "kurlbik & \"\\edge.d\" & \"ll\") = \"\"" ascii //weight: 1
        $x_1_3 = "Application.Run(\"hi\", RootPath)" ascii //weight: 1
        $x_1_4 = ".DefaultFilePath(wdStartupPath)" ascii //weight: 1
        $x_1_5 = "VBA.CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_6 = ".Run bcvsdsf & \" \" & oys" ascii //weight: 1
        $x_1_7 = "Call stetptwwo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_DR_2147779374_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.DR!MTB"
        threat_id = "2147779374"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ololow & \"\\plumbus.rik\" As pafh & \"\\\"" ascii //weight: 1
        $x_1_2 = "Options.DefaultFilePath(wdStartupPath)" ascii //weight: 1
        $x_1_3 = "iof & \".\" & ter & \"xe\"" ascii //weight: 1
        $x_1_4 = "(sf & \"\\plumbus.rik\") = \"\"" ascii //weight: 1
        $x_1_5 = "Application.Run(\"jop\", myhome, plop & \"\\wermgr.dll\")" ascii //weight: 1
        $x_1_6 = "Application.Run(\"hi\", RootPath)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EMTU_2147779581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EMTU!MTB"
        threat_id = "2147779581"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"\\edge.d\"" ascii //weight: 1
        $x_1_2 = "Dim jsd As String" ascii //weight: 1
        $x_1_3 = "Dim pus As String" ascii //weight: 1
        $x_1_4 = {2e 52 75 6e 20 66 61 20 26 20 22 20 22 20 26 20 79 79 2c 20 77 69 6e 64 6f 77 53 74 79 6c 65 2c 20 77 61 69 74 4f 6e 52 65 74 75 72 6e 02 00 45 6e 64 20 49 66 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EMTU_2147779581_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EMTU!MTB"
        threat_id = "2147779581"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If Dir(jos & \"\\edge.d\" & \"ll\") = \"\" Then" ascii //weight: 1
        $x_1_2 = "Set xcvxv = VBA.CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_3 = "xcvxv.Run bcvsdsf & \" \" & oys" ascii //weight: 1
        $x_1_4 = "Call q1(kf)" ascii //weight: 1
        $x_1_5 = "Dim pafh As String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EMTV_2147779582_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EMTV!MTB"
        threat_id = "2147779582"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"\\edge.d\"" ascii //weight: 1
        $x_1_2 = "& jsd & \"l\" & laz & hh" ascii //weight: 1
        $x_1_3 = "= ThisDocument.Tables(1).Cell(1, 1).Range.Text" ascii //weight: 1
        $x_1_4 = "Call rnee(uuu, aaaa)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EMTV_2147779582_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EMTV!MTB"
        threat_id = "2147779582"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If Dir(jos & \"\\ferus.d\" & \"l\" & \"l\") = \"\" Then" ascii //weight: 1
        $x_1_2 = "= ThisDocument.Tables(1).Cell(1, 1).Range.Text" ascii //weight: 1
        $x_1_3 = "Sub bcvxzc()" ascii //weight: 1
        $x_1_4 = "= Application.Run(\"nm\", ololow)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EMTS_2147779636_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EMTS!MTB"
        threat_id = "2147779636"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "edge.d" ascii //weight: 1
        $x_1_2 = "Application.Run(\"nm\", ololow)" ascii //weight: 1
        $x_1_3 = "Sub jop(uuu As String, aaaa As String)" ascii //weight: 1
        $x_1_4 = "Call rnee(uuu, aaaa)" ascii //weight: 1
        $x_1_5 = "Call stetptwwo" ascii //weight: 1
        $x_1_6 = "= VBA.CreateObject(\"WScript.Shell\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EMLW_2147779987_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EMLW!MTB"
        threat_id = "2147779987"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub nm(ololow As String)" ascii //weight: 1
        $x_1_2 = "Name ololow & \"\\murpus.m\" As pit & \"\\\" & \"hurpus.d\" & \"ll\"" ascii //weight: 1
        $x_1_3 = ".Run(\"nm\", ololow)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EMTW_2147780369_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EMTW!MTB"
        threat_id = "2147780369"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"\\urip.d\"" ascii //weight: 1
        $x_1_2 = "If Dir(jos & \"\\urip.d\" & \"l\" & \"l\") = \"\" Then" ascii //weight: 1
        $x_1_3 = "ThisDocument.Tables(1).Cell(1, 1).Range.Text" ascii //weight: 1
        $x_1_4 = "Set f = fs.GetFolder(Folder)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_VIS_2147783265_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.VIS!MTB"
        threat_id = "2147783265"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "run\" & \"dl\"" ascii //weight: 1
        $x_1_2 = "Alias \"ShellExecuteA\" (ByVal hwnd As Long, _" ascii //weight: 1
        $x_1_3 = "Option Explicit" ascii //weight: 1
        $x_1_4 = "If Dir(vcbc & \"\\kikus.dll\") = \"\" Then" ascii //weight: 1
        $x_1_5 = {76 63 62 63 20 26 20 22 5c 6b 69 6b 75 73 2e 64 6c 6c 2c [0-15] 22 2c 20 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_RVB_2147783410_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.RVB!MTB"
        threat_id = "2147783410"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Ters.Name = \"kiks.dll\"" ascii //weight: 1
        $x_1_2 = "dfbvc = \"al\" & \"\\Te\"" ascii //weight: 1
        $x_1_3 = "ewrwsdf = \"L\" & \"o\" & \"c\" & dfbvc & \"mp\"" ascii //weight: 1
        $x_1_4 = "oxl = \".dll\"" ascii //weight: 1
        $x_1_5 = {4e 61 6d 65 20 70 61 66 73 20 41 73 20 70 6c 73 20 26 20 22 5c [0-6] 6b 69 6b 75 73 22 20 26 20 6f 78 6c}  //weight: 1, accuracy: Low
        $x_1_6 = "Call uoia(Options.DefaultFilePath(wdUserTemplatesPath))" ascii //weight: 1
        $x_1_7 = "Each Nedc In mds.SubFolders" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOAD_2147785354_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOAD!MTB"
        threat_id = "2147785354"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fffff = \"ter.d\"" ascii //weight: 1
        $x_1_2 = "fffff = fffff & \"ll\"" ascii //weight: 1
        $x_1_3 = "For Each Nedc In mds.SubFolders" ascii //weight: 1
        $x_1_4 = "Call ThisDocument.hdhdd(Left(Options.DefaultFilePath(wdUserTemplatesPath), ntgs) & ewrwsdf)" ascii //weight: 1
        $x_1_5 = "Name pafs As pls & oxl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOAE_2147786545_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOAE!MTB"
        threat_id = "2147786545"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Name pafs As Environ$(\"temp\") & \"\\\" & \"omsh.dll\"" ascii //weight: 1
        $x_1_2 = {49 66 20 54 65 72 73 2e 4e 61 6d 65 20 3d 20 22 [0-4] 2e 64 6c 6c 22 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_3 = "For Each Nedc In mds.SubFolders" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOAG_2147786546_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOAG!MTB"
        threat_id = "2147786546"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Environ$(\"temp\") & \"\\omsh.dll," ascii //weight: 1
        $x_1_2 = "usx = Environ$(\"temp\")" ascii //weight: 1
        $x_1_3 = {41 63 74 69 76 65 53 68 65 65 74 2e 53 68 61 70 65 73 2e 52 61 6e 67 65 28 41 72 72 61 79 28 22 4f 62 6a 65 63 74 20 [0-3] 22 29 29 2e 53 65 6c 65 63 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_DRP_2147786570_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.DRP!MTB"
        threat_id = "2147786570"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellExecuteA\" (ByVal" ascii //weight: 1
        $x_1_2 = "Environ$(\"temp\")" ascii //weight: 1
        $x_1_3 = "(vcbc & \"\\omsh.dll\")" ascii //weight: 1
        $x_1_4 = "Call Search(asdaf." ascii //weight: 1
        $x_1_5 = "Environ$(\"temp\") & \"\\omsh.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_DP_2147787312_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.DP!MTB"
        threat_id = "2147787312"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"Local/Temp\"" ascii //weight: 1
        $x_1_2 = "(vcbc & \"\\qq.doc\")" ascii //weight: 1
        $x_1_3 = "Call bvxfcsd" ascii //weight: 1
        $x_1_4 = "\"qq.fax\"" ascii //weight: 1
        $x_1_5 = "Call Search(MyFSO.GetFolder(asda), hdv)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOAS_2147788352_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOAS!MTB"
        threat_id = "2147788352"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call ousx" ascii //weight: 1
        $x_1_2 = "Dim oxl" ascii //weight: 1
        $x_1_3 = "oxl = \"\\glib.doc\"" ascii //weight: 1
        $x_1_4 = "Name pafs As pls & oxl" ascii //weight: 1
        $x_1_5 = "Call uoia(Options.DefaultFilePath(wdUserTemplatesPath))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOAT_2147788353_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOAT!MTB"
        threat_id = "2147788353"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If Dir(vcbc & \"\\glib.d\" & \"oc\") = \"\" Then" ascii //weight: 1
        $x_1_2 = "Documents.Open FileName:=vcbc & \"\\glib.d\" & \"oc\", ConfirmConversions:=False, ReadOnly:= _" ascii //weight: 1
        $x_1_3 = "Call nam(hdv)" ascii //weight: 1
        $x_1_4 = "Call bvxfcsd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_BK_2147788461_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.BK!MTB"
        threat_id = "2147788461"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If Dir(Left(uuuuc, ntgs) & ewrwsdf, vbDirectory) = \"\" Then" ascii //weight: 1
        $x_1_2 = "Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & ewrwsdf)" ascii //weight: 1
        $x_1_3 = "If Dir(vcbc & \"\\glib.d\" & \"oc\") = \"\" Then" ascii //weight: 1
        $x_1_4 = "Call Search(MyFSO.GetFolder(asda), hdv)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_RVD_2147789058_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.RVD!MTB"
        threat_id = "2147789058"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call Search(MyFSO.GetFolder(asda), hdv)" ascii //weight: 1
        $x_1_2 = "Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & ewrwsdf)" ascii //weight: 1
        $x_1_3 = "oxl = \"\\glib.d\" & \"o\" & \"c\"" ascii //weight: 1
        $x_1_4 = "Options.DefaultFilePath(wdUserTemplatesPath)" ascii //weight: 1
        $x_1_5 = "fffff = \"glib.b\" & \"ax\"" ascii //weight: 1
        $x_1_6 = ".Open FileName:=vcbc & \"\\glib.d\" & \"o\" & \"c\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOAU_2147789099_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOAU!MTB"
        threat_id = "2147789099"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Documents.Open FileName:=vcbc & \"\\glib.d\" & \"o\" & \"c\", ConfirmConversions:=False, ReadOnly:= _" ascii //weight: 1
        $x_1_2 = "If Dir(vcbc & \"\\glib.d\" & \"o\" & \"c\") = \"\" Then" ascii //weight: 1
        $x_1_3 = "Call bvxfcsd" ascii //weight: 1
        $x_1_4 = "AddToRecentFiles:=False, PasswordDocument:=\"123321\", _" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOAV_2147789100_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOAV!MTB"
        threat_id = "2147789100"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fffff = \"glib.b\" & \"ax\"" ascii //weight: 1
        $x_1_2 = "oxl = \"\\glib.d\" & \"o\" & \"c\"" ascii //weight: 1
        $x_1_3 = "ewrwsdf = ewrwsdf & \"Temp\"" ascii //weight: 1
        $x_1_4 = "Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & ewrwsdf)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOAW_2147789259_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOAW!MTB"
        threat_id = "2147789259"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\glib.d\" & \"o\" & \"c\"" ascii //weight: 1
        $x_1_2 = "ewrwsdf = \"Loc\" & \"a\" & \"l/\"" ascii //weight: 1
        $x_1_3 = "If Dir(Left(uuuuc, ntgs) & kuls, vbDirectory) = \"\" Then" ascii //weight: 1
        $x_1_4 = "uuuuc = Options.DefaultFilePath(wdUserTemplatesPath)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOAX_2147789260_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOAX!MTB"
        threat_id = "2147789260"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call Search(MyFSO.GetFolder(asda), hdv)" ascii //weight: 1
        $x_1_2 = "Call pppx(vcbc & \"\\glib.d\" & \"o\" & \"c\")" ascii //weight: 1
        $x_1_3 = "If Dir(vcbc & \"\\glib.d\" & \"o\" & \"c\") = \"\" Then" ascii //weight: 1
        $x_1_4 = "Dim dfgdgdg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOAZ_2147789261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOAZ!MTB"
        threat_id = "2147789261"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\glib.d\" & \"o\" & \"c\"" ascii //weight: 1
        $x_1_2 = "Sub pppx(spoc As String)" ascii //weight: 1
        $x_1_3 = "Documents.Open FileName:=spoc, ConfirmConversions:=False, ReadOnly:= _" ascii //weight: 1
        $x_1_4 = "Call uoia(Options.DefaultFilePath(wdUserTemplatesPath))" ascii //weight: 1
        $x_1_5 = "Sub ousx()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBA_2147792978_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBA!MTB"
        threat_id = "2147792978"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"\\gl\" & \"ib.d\" & \"o\" & \"c\"" ascii //weight: 1
        $x_1_2 = "Call uoia(Options.DefaultFilePath(wdUserTemplatesPath))" ascii //weight: 1
        $x_1_3 = "Sub pppx(spoc As String)" ascii //weight: 1
        $x_1_4 = "False, AddToRecentFiles:=False, PasswordDocument:=\"123321\", _" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBB_2147792979_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBB!MTB"
        threat_id = "2147792979"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"\\gl\" & \"ib.d\" & \"o\" & \"c\"" ascii //weight: 1
        $x_1_2 = "ewrwsdf = \"Loc\" & \"a\" & \"l\"" ascii //weight: 1
        $x_1_3 = "ewrwsdf = ewrwsdf & \"/\" & \"Temp\"" ascii //weight: 1
        $x_1_4 = "Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & ewrwsdf)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBC_2147792980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBC!MTB"
        threat_id = "2147792980"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fffff = \"gl\" & \"ib.b\" & \"ax\"" ascii //weight: 1
        $x_1_2 = "oxl = \"\\gl\" & \"ib.d\" & \"o\" & \"c\"" ascii //weight: 1
        $x_1_3 = "For Each Nedc In mds.SubFolders" ascii //weight: 1
        $x_1_4 = "Call ousx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBD_2147793600_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBD!MTB"
        threat_id = "2147793600"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\reform.doc\"" ascii //weight: 1
        $x_1_2 = "Sub pppx(spoc As String)" ascii //weight: 1
        $x_1_3 = "False, AddToRecentFiles:=False, PasswordDocument:=\"2281337\", _" ascii //weight: 1
        $x_1_4 = "Call uoia(aaaa)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBE_2147793601_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBE!MTB"
        threat_id = "2147793601"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call ousx" ascii //weight: 1
        $x_1_2 = "oxl = \"\\reform.doc\"" ascii //weight: 1
        $x_1_3 = "fffff = \"reform.ioe\"" ascii //weight: 1
        $x_1_4 = "Attribute VB_Name = \"Module123345\"" ascii //weight: 1
        $x_1_5 = "Sub uoia(fffs As String)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBF_2147793602_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBF!MTB"
        threat_id = "2147793602"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reform.doc" ascii //weight: 1
        $x_1_2 = "fafaa = fafaa & \"c\" & \"a\" & \"l\"" ascii //weight: 1
        $x_1_3 = "fafaa = fafaa & \"/\" & \"Temp\"" ascii //weight: 1
        $x_1_4 = "Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & fafaa)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBG_2147793603_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBG!MTB"
        threat_id = "2147793603"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If Dir(kytrewwf & \"\\reform.doc\") = \"\" Then" ascii //weight: 1
        $x_1_2 = "Call pppx(kytrewwf & \"\\reform.doc\")" ascii //weight: 1
        $x_1_3 = "Call Search(MyFSO.GetFolder(asda), hdv)" ascii //weight: 1
        $x_1_4 = "Sub hdhdd(asda As String)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBH_2147793911_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBH!MTB"
        threat_id = "2147793911"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub nam(pafs As String, aaaa As String)" ascii //weight: 1
        $x_1_2 = "Call ousx(aaaa)" ascii //weight: 1
        $x_1_3 = "Dim oxl" ascii //weight: 1
        $x_1_4 = "oxl = \"\\reform\" & \".doc\"" ascii //weight: 1
        $x_1_5 = "Name pafs As pls & oxl" ascii //weight: 1
        $x_1_6 = "Sub uoia(fffs As String)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBI_2147793912_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBI!MTB"
        threat_id = "2147793912"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reform.doc" ascii //weight: 1
        $x_1_2 = "fafaa = fafaa & \"/\"" ascii //weight: 1
        $x_1_3 = "fafaa = fafaa & \"T\" & \"e\"" ascii //weight: 1
        $x_1_4 = "fafaa = fafaa & \"mp\"" ascii //weight: 1
        $x_1_5 = "Dim kuls As String" ascii //weight: 1
        $x_1_6 = "Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & fafaa)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBJ_2147793913_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBJ!MTB"
        threat_id = "2147793913"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub pppx(spoc As String)" ascii //weight: 1
        $x_1_2 = "False, AddToRecentFiles:=False, PasswordDocument:=\"2281337\", _" ascii //weight: 1
        $x_1_3 = "Sub ousx(aaaa As String)" ascii //weight: 1
        $x_1_4 = "Call uoia(aaaa)" ascii //weight: 1
        $x_1_5 = "\"\\reform\" & \".d\" & \"oc\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBK_2147794062_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBK!MTB"
        threat_id = "2147794062"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub nam(pafs As String, aaaa As String)" ascii //weight: 1
        $x_1_2 = "Call ousx(aaaa)" ascii //weight: 1
        $x_1_3 = "Dim oxl" ascii //weight: 1
        $x_1_4 = "oxl = \"\\reform\" & \".d\" & \"oc\"" ascii //weight: 1
        $x_1_5 = "Name pafs As pls & oxl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBL_2147794130_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBL!MTB"
        threat_id = "2147794130"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If Dir(kytrewwf & \"\\\" & \"reform\" & \".doc\") = \"\" Then" ascii //weight: 1
        $x_1_2 = "Call pppx(kytrewwf & \"\\\" & \"reform\" & \".doc\")" ascii //weight: 1
        $x_1_3 = "Call Search(MyFSO.GetFolder(asda), hdv)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBM_2147794369_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBM!MTB"
        threat_id = "2147794369"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub nam(pafs As String, aaaa As String)" ascii //weight: 1
        $x_1_2 = "Call ousx(aaaa)" ascii //weight: 1
        $x_1_3 = "Dim abrakadabra As String" ascii //weight: 1
        $x_1_4 = "abrakadabra = \"o\"" ascii //weight: 1
        $x_1_5 = "abrakadabra = abrakadabra & \"c\"" ascii //weight: 1
        $x_1_6 = "Dim oxl" ascii //weight: 1
        $x_1_7 = "oxl = \"\\diplo.d\" & abrakadabra" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBN_2147794370_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBN!MTB"
        threat_id = "2147794370"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & fafaa)" ascii //weight: 1
        $x_1_2 = "\"\\diplo.d\" & abrakadabra" ascii //weight: 1
        $x_1_3 = "Call Search(MyFSO.GetFolder(asda), hdv)" ascii //weight: 1
        $x_1_4 = "Call bvxfcsd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBO_2147794460_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBO!MTB"
        threat_id = "2147794460"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "False, AddToRecentFiles:=False, PasswordDocument:=\"2281337\", _" ascii //weight: 1
        $x_1_2 = "fffff = \"diplo.i\" & siplo" ascii //weight: 1
        $x_1_3 = "Call uoia(aaaa)" ascii //weight: 1
        $x_1_4 = "Call s2(\"cal/\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBP_2147794461_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBP!MTB"
        threat_id = "2147794461"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call pppx(kytrewwf & \"\\diplo.d\" & abrakadabra)" ascii //weight: 1
        $x_1_2 = "Call pppx(kytrewwf & fds & \"di\" & \"plo\" & fdsa & vssfs)" ascii //weight: 1
        $x_1_3 = "Dim vv1, vv2, vv3, vv4, fafaa As String" ascii //weight: 1
        $x_1_4 = "If Dir(Left(uuuuc, ntgs) & kuls, vbDirectory) = \"\" Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBQ_2147794528_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBQ!MTB"
        threat_id = "2147794528"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If Dir(kytrewwf & fds & \"di\" & \"plo\" & fdsa & vssfs) = \"\" Then" ascii //weight: 1
        $x_1_2 = "fdsa = \".d\"" ascii //weight: 1
        $x_1_3 = "Call uoia(aaaa)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBS_2147794843_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBS!MTB"
        threat_id = "2147794843"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fdsa = \".d\"" ascii //weight: 1
        $x_1_2 = "If Dir(kytrewwf & fds & \"zoro\" & fdsa & vssfs)" ascii //weight: 1
        $x_1_3 = "Call pppx(kytrewwf & fds & \"zoro\" & fdsa & vssfs)" ascii //weight: 1
        $x_1_4 = "Application.Run(\"bvxfcsd\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBT_2147794844_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBT!MTB"
        threat_id = "2147794844"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If Dir(Left(uuuuc, ntgs) & fafaa, vbDirectory) = \"\" Then" ascii //weight: 1
        $x_1_2 = "Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & fafaa)" ascii //weight: 1
        $x_1_3 = "Dim mgf, uhjknb, wers, qweds, fafaa As String" ascii //weight: 1
        $x_1_4 = "Dim uuuuc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBU_2147794845_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBU!MTB"
        threat_id = "2147794845"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zoro.kl" ascii //weight: 1
        $x_1_2 = "oxl = \"\\zoro.d\"" ascii //weight: 1
        $x_1_3 = "oxl = oxl & \"oc\"" ascii //weight: 1
        $x_1_4 = "Call uoia(aaaa)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBV_2147794846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBV!MTB"
        threat_id = "2147794846"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zoro.d" ascii //weight: 1
        $x_1_2 = "Sub pppx(pili As String)" ascii //weight: 1
        $x_1_3 = "False, AddToRecentFiles:=False, PasswordDocument:=\"doyouknowthatthegodsofdeathonlyeatapples?" ascii //weight: 1
        $x_1_4 = "Call s2(\"cal/\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBW_2147795321_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBW!MTB"
        threat_id = "2147795321"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If Dir(fds & \"zo\" & \"ro\" & fdsa & vssfs) = \"\" Then" ascii //weight: 1
        $x_1_2 = "mySum = Application.Run(\"ppl\")" ascii //weight: 1
        $x_1_3 = "Call pppx(fds & \"zo\" & \"ro\" & fdsa & vssfs)" ascii //weight: 1
        $x_1_4 = "Call ass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBX_2147795322_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBX!MTB"
        threat_id = "2147795322"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oxl = \"\\zoro.\" & \"d" ascii //weight: 1
        $x_1_2 = "oxl = oxl & \"o" ascii //weight: 1
        $x_1_3 = "Name pafs As pls & oxl" ascii //weight: 1
        $x_1_4 = "Call uoia(aaaa)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBY_2147795323_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBY!MTB"
        threat_id = "2147795323"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"\\zoro.\" & \"d" ascii //weight: 1
        $x_1_2 = "= \"zoro.kl\" Then" ascii //weight: 1
        $x_1_3 = "Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & tini)" ascii //weight: 1
        $x_1_4 = "Call Search(MyFSO.GetFolder(asda), lds)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_EOBZ_2147795324_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.EOBZ!MTB"
        threat_id = "2147795324"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If Ters.Name = \"zoro.kl\" Then" ascii //weight: 1
        $x_1_2 = "Dim mgf, uhjknb, wers, qweds, fafaa As String" ascii //weight: 1
        $x_1_3 = "Call bvxfcsd(poidds)" ascii //weight: 1
        $x_1_4 = "False, AddToRecentFiles:=False, PasswordDocument:=\"doyouknowthatthegodsofdeathonlyeatapples?\", _" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_PAYS_2147796665_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.PAYS!MTB"
        threat_id = "2147796665"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Options.DefaultFilePath(wdUserTemplatesPath)" ascii //weight: 1
        $x_1_2 = "Application.Run(\"ppl\")" ascii //weight: 1
        $x_1_3 = "Len(lds) > 2 Then" ascii //weight: 1
        $x_1_4 = "Call pppx(fds & \"zo\" & \"r\" & \"o\" & fdsa & vssfs)" ascii //weight: 1
        $x_1_5 = "Call Search(MyFSO.GetFolder(asda), lds)" ascii //weight: 1
        $x_1_6 = "PasswordDocument:=\"doyouknowthatthegodsofdeathonlyeatapples?\"" ascii //weight: 1
        $x_1_7 = "Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & tini)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JOAA_2147796733_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JOAA!MTB"
        threat_id = "2147796733"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub pppx(pili As String)" ascii //weight: 1
        $x_1_2 = "Call oicx(pili)" ascii //weight: 1
        $x_1_3 = "False, AddToRecentFiles:=False, PasswordDocument:=\"doyouknowthatthegodsofdeathonlyeatapples?" ascii //weight: 1
        $x_1_4 = "zo\" & \"ro.\" & \"d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JOAB_2147796734_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JOAB!MTB"
        threat_id = "2147796734"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oxl = \"\\zo\" & \"ro.\" & \"d" ascii //weight: 1
        $x_1_2 = "oxl = oxl & \"o" ascii //weight: 1
        $x_1_3 = "oxl = oxl & \"c" ascii //weight: 1
        $x_1_4 = "Name pafs As pls & oxl" ascii //weight: 1
        $x_1_5 = "Call uoia(aaaa)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JOAC_2147796735_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JOAC!MTB"
        threat_id = "2147796735"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "poidds = mgf & uhjknb & \"\" & wers & mfd & qweds & ugfc" ascii //weight: 1
        $x_1_2 = "Call bvxfcsd(lklc)" ascii //weight: 1
        $x_1_3 = "Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & tini)" ascii //weight: 1
        $x_1_4 = "Call pppx(fds & \"zo\" & \"r\" & \"o\" & fdsa & vssfs)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JOAD_2147798059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JOAD!MTB"
        threat_id = "2147798059"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Documents.Open FileName:=Options.DefaultFilePath(wdUserTemplatesPath) & \"\\zoro.doc\", ConfirmConversions:=False, ReadOnly:= _" ascii //weight: 1
        $x_1_2 = "Call bvxfcsd" ascii //weight: 1
        $x_1_3 = "Sub pppx()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JOAE_2147798060_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JOAE!MTB"
        threat_id = "2147798060"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call Primer1(Folder & \"\\\" & f1.Name & \"\\\")" ascii //weight: 1
        $x_1_2 = "Sub Subfolders_in(Folder$)" ascii //weight: 1
        $x_1_3 = "Call bvxfcsd" ascii //weight: 1
        $x_1_4 = "Dim fso, myFolder, myFile, myFiles(), i" ascii //weight: 1
        $x_1_5 = "Call Subfolders_in(Left(uuuuc, ntgs) & \"\\Local\\\" & \"Temp\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JOAF_2147798061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JOAF!MTB"
        threat_id = "2147798061"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\zoro.doc" ascii //weight: 1
        $x_1_2 = "Call Primer1(Left(uuuuc, ntgs) & \"\\Local\\\" & \"Temp\")" ascii //weight: 1
        $x_1_3 = "uuuuc = Options.DefaultFilePath(wdUserTemplatesPath" ascii //weight: 1
        $x_1_4 = "Call pppx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_AM_2147798457_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.AM!MTB"
        threat_id = "2147798457"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bcbdf = bcbdf & jj" ascii //weight: 1
        $x_1_2 = "Call ThisDocument.hfdwesdf" ascii //weight: 1
        $x_1_3 = "Call miko(bcbdf, \"d\" & \"o\" & \"c\")" ascii //weight: 1
        $x_1_4 = "vv = \"p.\" & vf" ascii //weight: 1
        $x_1_5 = "Call mm(\"kukumar1s.r\" & pxc)" ascii //weight: 1
        $x_1_6 = "Call mm(\"h\" & \"t\" & klx)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JOAH_2147798535_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JOAH!MTB"
        threat_id = "2147798535"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\zoro.d\" & \"oc" ascii //weight: 1
        $x_1_2 = "Dim uuuuc" ascii //weight: 1
        $x_1_3 = "Call ThisDocument.Subfolders_in(Left(uuuuc, ntgs) & \"Loc\" & \"\" & \"a\" & fk1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JOAI_2147798536_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JOAI!MTB"
        threat_id = "2147798536"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Name myFile.path As Options.DefaultFilePath(wdUserTemplatesPath) & \"\\zoro.doc" ascii //weight: 1
        $x_1_2 = "Call pppx" ascii //weight: 1
        $x_1_3 = "Set myFolder = fso.GetFolder(myPath)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JOAK_2147798611_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JOAK!MTB"
        threat_id = "2147798611"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zoro.\" & \"k\" & \"l" ascii //weight: 1
        $x_1_2 = "Call Primer1(Folder & \"\\\" & f1.Name & \"\\\")" ascii //weight: 1
        $x_1_3 = "Call bvxfcsd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_RVC_2147805954_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.RVC!MTB"
        threat_id = "2147805954"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Options.DefaultFilePath(wdUserTemplatesPath) & \"\\iff\" & \".bin\"" ascii //weight: 1
        $x_1_2 = "Documents.Open fileName:=vxc & \"help.d\" & \"oc\", PasswordDocument:=\"donttouchme\"" ascii //weight: 1
        $x_1_3 = "= vxc & \"frolol0.ru/\"" ascii //weight: 1
        $x_1_4 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 43 61 6c 6c 20 6f 6f 61 73 70 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JOAZ_2147806036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JOAZ!MTB"
        threat_id = "2147806036"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 6f 6f 61 73 70 70 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {43 61 6c 6c 20 6f 69 31 02 00 43 61 6c 6c 20 6f 69 63 02 00 43 61 6c 6c 20 6b 62 76 63}  //weight: 1, accuracy: Low
        $x_1_3 = {44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 20 66 69 6c 65 4e 61 6d 65 3a 3d 76 78 63 20 26 20 22 [0-8] 2e 64 22 20 26 20 22 6f 63 22 2c 20 50 61 73 73 77 6f 72 64 44 6f 63 75 6d 65 6e 74 3a 3d 22 64 6f 6e 74 74 6f 75 63 68 6d 65}  //weight: 1, accuracy: Low
        $x_1_4 = "vxc = vxc & \"htt" ascii //weight: 1
        $x_1_5 = "Sub kbvc()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_RVE_2147807943_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.RVE!MTB"
        threat_id = "2147807943"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Options.DefaultFilePath(wdUserTemplatesPath) & \"\\iff\" & \".bin\"" ascii //weight: 1
        $x_1_2 = "Call mm(\"0bamandos.r\" & \"u/\")" ascii //weight: 1
        $x_1_3 = "Documents.Open fileName:=vxc & \"hel\" & vv, PasswordDocument:=\"44\"" ascii //weight: 1
        $x_1_4 = "Call miko(bcbdf, \"p.d\" & \"oc\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JOBA_2147807978_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JOBA!MTB"
        threat_id = "2147807978"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bcbdf = bcbdf & \"htt" ascii //weight: 1
        $x_1_2 = "Call ThisDocument.hfdwesdf" ascii //weight: 1
        $x_1_3 = "Call xcvsdfs" ascii //weight: 1
        $x_1_4 = "p.d\" & \"oc\")" ascii //weight: 1
        $x_1_5 = "Call ooaspp" ascii //weight: 1
        $x_1_6 = "Call mm(\"p://\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_PAX_2147808045_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.PAX!MTB"
        threat_id = "2147808045"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If Dir(uu & \"\\iff\" & \".bin\", vbDirectory) = \"\" Then" ascii //weight: 1
        $x_1_2 = "Call mm(\"sineko7.r\" & \"u/\")" ascii //weight: 1
        $x_1_3 = "Call miko(bcbdf, \"d\" & \"oc\")" ascii //weight: 1
        $x_1_4 = "Documents.Open fileName:=vxc & \"hel\" & vv, PasswordDocument:=\"44" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_SS_2147811286_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.SS!MTB"
        threat_id = "2147811286"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call miko(bcbdf, \"d\" & \"o\" & \"c\")" ascii //weight: 1
        $x_1_2 = "Call mm(\"tropitron5.r\" & \"u/\")" ascii //weight: 1
        $x_1_3 = "(uu & \"\\iff\" & plf & \"b\" & \"in\", vbDirectory)" ascii //weight: 1
        $x_1_4 = "Documents.Open fileName:=vxc & \"hel\" & vv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_SS_2147811286_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.SS!MTB"
        threat_id = "2147811286"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 6d 6d 28 22 [0-15] 2e 72 22 20 26 20 22 75 2f 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "Documents.Open fileName:=vxc & \"hel\" & vv" ascii //weight: 1
        $x_1_3 = "If Dir(uu & \"\\iff\" & plf & \"b\" & \"i\" & \"n\", vbDirectory) = \"\" Then" ascii //weight: 1
        $x_1_4 = "Call miko(bcbdf, \"d\" & \"o\" & \"c\")" ascii //weight: 1
        $x_1_5 = "Call mm(\"h\" & \"t\" & klx)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JOBC_2147811330_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JOBC!MTB"
        threat_id = "2147811330"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call ThisDocument.hfdwesdf" ascii //weight: 1
        $x_1_2 = "Call xcvsdfs" ascii //weight: 1
        $x_1_3 = "Call mm(\"p:\" & \"//\")" ascii //weight: 1
        $x_1_4 = "If Dir(uu & \"\\iff\" & plf & \"b\" & \"in\", vbDirectory) = \"\" Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JOBD_2147811331_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JOBD!MTB"
        threat_id = "2147811331"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 64 73 73 64 66 28 29 02 00 43 61 6c 6c 20 6d 6d 28 22 68 22 20 26 20 22 74 22 20 26 20 22 74 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {43 61 6c 6c 20 6b 6d 02 00 44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 20 66 69 6c 65 4e 61 6d 65 3a 3d 76 78 63 20 26 20 22 68 65 6c 22 20 26 20 76 76 2c 20 50 61 73 73 77 6f 72 64 44 6f 63 75 6d 65 6e 74 3a 3d 22 34 34}  //weight: 1, accuracy: Low
        $x_1_3 = "Sub mm(jj As String)" ascii //weight: 1
        $x_1_4 = "bcbdf = bcbdf & jj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_JOBE_2147812635_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.JOBE!MTB"
        threat_id = "2147812635"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub hfdwesdf()" ascii //weight: 1
        $x_1_2 = "Call mm(\"p:\" & \"//\")" ascii //weight: 1
        $x_1_3 = "Call xcvsdfs" ascii //weight: 1
        $x_1_4 = "If Dir(uu & \"\\moe\" & \"xx\" & plf & \"b\" & \"i\" & \"n\", vbDirectory) = \"\" Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Hancitor_RVF_2147815404_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Hancitor.RVF!MTB"
        threat_id = "2147815404"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 43 61 6c 6c 20 73 73 73}  //weight: 1, accuracy: High
        $x_1_2 = "= \"borw4.d\" & \"oc\"" ascii //weight: 1
        $x_1_3 = ".Open FileName:=strReturn, PasswordDocument:=\"44\"" ascii //weight: 1
        $x_1_4 = "Call Search(sfxcv.GetFolder(Options.DefaultFilePath(wdTempFilePath)))" ascii //weight: 1
        $x_1_5 = "koka = \"\\borw4.doc\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

