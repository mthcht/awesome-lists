rule TrojanDownloader_O97M_IcedId_BI_2147762348_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedId.BI!MTB"
        threat_id = "2147762348"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"p,:,\\,j,v,a,q,b,j,f,\\,f,l,f,g,r,z,3,2,\\,z,f,u,g,n,.,r,k,r,\"" ascii //weight: 1
        $x_1_2 = "= aZfl2W(Replace(ayZIm, aNJ2Rn, \"\"))" ascii //weight: 1
        $x_1_3 = "atbuRc.exec aOl4Bh" ascii //weight: 1
        $x_1_4 = "aR1Uh (aGR9b & \" \" & a5RXj)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedId_BI_2147762348_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedId.BI!MTB"
        threat_id = "2147762348"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_2 = "b1efc47a.f047ca69 f39e930a(0) + \" \" + f5244208" ascii //weight: 1
        $x_1_3 = "Call af8a301a.exec(f0032c5f)" ascii //weight: 1
        $x_1_4 = "= Split(ActiveDocument.Shapes(d0e6cdde).Title, \"|\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedId_BI_2147762348_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedId.BI!MTB"
        threat_id = "2147762348"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_2 = "df6dee5a.f7413504 ccb12773(0) + \" \" + f7647a17" ascii //weight: 1
        $x_1_3 = "Call d73c0afc.exec(b5108af6)" ascii //weight: 1
        $x_1_4 = "= Split(ActiveDocument.Shapes(c07e0738).Title, \"|\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedId_DR_2147769243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedId.DR!MTB"
        threat_id = "2147769243"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 65 78 65 63 20 28 [0-7] 28 [0-6] 29 20 26 20 22 20 22 20 26 20 [0-7] 20 26 20 22 2c 53 68 6f 77 44 69 61 6c 6f 67 41 20 2d 72 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 70 6c 69 74 28 [0-7] 2c 20 [0-6] 29}  //weight: 1, accuracy: Low
        $x_1_3 = "With ActiveDocument.Shapes(1#)" ascii //weight: 1
        $x_1_4 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-7] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 2d 2d 2d 2d 2d 22}  //weight: 1, accuracy: Low
        $x_1_5 = {53 65 74 20 ?? ?? ?? ?? ?? 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 ?? ?? ?? ?? ?? 28 33 29 20 26 20 22 2e 22 20 26 20 ?? ?? ?? ?? ?? 28 33 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29}  //weight: 1, accuracy: Low
        $x_1_6 = {6f 53 74 72 65 61 6d 2e 53 61 76 65 54 6f 46 69 6c 65 20 [0-7] 2c 20 32 02 00 6f 53 74 72 65 61 6d 2e 43 6c 6f 73 65 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_7 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-7] 28 [0-7] 29 02 00 27}  //weight: 1, accuracy: Low
        $x_1_8 = {3d 20 2e 61 6c 74 65 72 6e 61 74 69 76 65 74 65 78 74 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_9 = {70 72 6f 67 72 61 6d 64 61 74 61 5c ?? ?? ?? ?? ?? 2e 70 64 66}  //weight: 1, accuracy: Low
        $x_1_10 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 ?? ?? ?? ?? ?? 28 ?? ?? ?? ?? ?? 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedId_BK_2147770518_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedId.BK!MTB"
        threat_id = "2147770518"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Split(aqMXZ9(frm.paths.text), \"|\")" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"wscript.shell\").exec(aJNyC)" ascii //weight: 1
        $x_1_3 = "Application.Run \"avVfeb\", a14bvc & \" \" & axYjG & \"mat : \"\"\" & aUz3Cc &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedId_BK_2147770518_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedId.BK!MTB"
        threat_id = "2147770518"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\\" & Application.Version & \"\\Word\\Security\\AccessVBOM\"" ascii //weight: 1
        $x_1_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 52 65 67 57 72 69 74 65 20 [0-30] 2c 20 31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 4d 69 64 28 [0-30] 2c 20 34 20 2f 20 32 2c 20 33 30 30 30 30 30 30 29}  //weight: 1, accuracy: Low
        $x_1_4 = "= GetObject(\"\", \"word.application\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedId_SS_2147771461_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedId.SS!MTB"
        threat_id = "2147771461"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 [0-22] 2c 20 [0-21] 2c 20 32 29 29 29 [0-3] 4e 65 78 74 20 01 [0-3] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 4f 70 65 6e 20 [0-32] 28 22 34 37 34 35 35 34 22 29 2c 20 [0-48] 28 22 36 38 37 34 37 34 37 30 33 61 [0-48] 22 29 20 26 20 [0-37] 28 22 32 66 [0-54] 22 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = {44 69 6d 20 78 48 74 74 70 3a 20 53 65 74 20 [0-32] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-48] 28 22 34 64 36 39 36 33 37 32 36 66 37 33 36 66 36 36 37 34 32 65 35 38 34 64}  //weight: 1, accuracy: Low
        $x_1_4 = {44 69 6d 20 62 53 74 72 6d 3a 20 53 65 74 20 [0-32] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-48] 28 22 34 31 36 34 36 66 36 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedId_SSA_2147777953_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedId.SSA!MTB"
        threat_id = "2147777953"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 20 [0-15] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 56 42 53 63 72 69 70 74 2e 52 65 67 45 78 70 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 41 72 72 61 79 28 [0-15] 29 [0-7] 57 69 74 68}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 50 61 74 74 65 72 6e 20 3d 20 22 ?? 7c ?? 7c ?? 7c ?? 7c ?? 7c}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 47 6c 6f 62 61 6c 20 3d 20 54 72 75 65 [0-8] 45 6e 64 20 57 69 74 68}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 52 65 70 6c 61 63 65 28 [0-15] 28 30 29 2c 20 22 22 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

