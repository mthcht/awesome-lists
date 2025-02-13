rule TrojanDownloader_O97M_IcedID_PCE_2147762498_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PCE!MTB"
        threat_id = "2147762498"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "db.exec(a69f5c12)" ascii //weight: 1
        $x_1_2 = "CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_3 = "cf.Open \"GET\", aa7d93ad" ascii //weight: 1
        $x_1_4 = "beabd2cf.Send" ascii //weight: 1
        $x_1_5 = "aa = .responsebody" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PCF_2147762499_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PCF!MTB"
        threat_id = "2147762499"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d3.exec(b1e5f5df)" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_3 = "= .responsebody" ascii //weight: 1
        $x_1_4 = "240.Open \"GET\", f1dbbb5f" ascii //weight: 1
        $x_1_5 = "cee60240.Send" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PCG_2147762500_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PCG!MTB"
        threat_id = "2147762500"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_2 = "Call d7d3054e.exec(f0a36a45)" ascii //weight: 1
        $x_1_3 = "c41e6bcc.Open \"GET\", fab6f8e5(" ascii //weight: 1
        $x_1_4 = "c41e6bcc.Send" ascii //weight: 1
        $x_1_5 = "b342af0c = .responsebody" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PCH_2147762501_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PCH!MTB"
        threat_id = "2147762501"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_2 = "Call cdda5fda.exec(e6fd511c)" ascii //weight: 1
        $x_1_3 = "af92bcf0.Open \"GET\", f12ec170" ascii //weight: 1
        $x_1_4 = "af92bcf0.Send" ascii //weight: 1
        $x_1_5 = "cedfe73b = .responsebody" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PCK_2147762625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PCK!MTB"
        threat_id = "2147762625"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "f0ca199d.cdb106ad f21bf1f6(0) + \" \" + e3263784" ascii //weight: 1
        $x_1_2 = "= Split(f9973bea, \"|\")" ascii //weight: 1
        $x_1_3 = "aeff4ab4.exec(f41f54a6)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PCL_2147762731_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PCL!MTB"
        threat_id = "2147762731"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Split(af677688, \"|\")" ascii //weight: 1
        $x_1_2 = "dfe79bd7 = CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_3 = "dfe79bd7.exec(cb3cbe53)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PCJ_2147762954_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PCJ!MTB"
        threat_id = "2147762954"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FileNumber = FreeFile" ascii //weight: 1
        $x_1_2 = {50 72 69 6e 74 20 23 46 69 6c 65 4e 75 6d 62 65 72 2c 20 53 70 63 28 [0-15] 29}  //weight: 1, accuracy: Low
        $x_1_3 = "FileCopy" ascii //weight: 1
        $x_1_4 = "If (x% > 64 And x% < 91) Or (x% > 96 And x% < 123)" ascii //weight: 1
        $x_1_5 = "If x% < 97 And x% > 83 Then x% = x% + 26 Else If x% < 65 Then x% = x% + 26" ascii //weight: 1
        $x_1_6 = {4d 69 64 24 28 [0-10] 24 2c 20 74 74 2c 20 31 29 20 3d 20 43 68 72 24 28 78 25 29}  //weight: 1, accuracy: Low
        $x_1_7 = "= \"p,:,\\,j,v,a,q,b,j,f,\\,f,l,f,g,r,z,3,2,\\,z,f,u,g,n,.,r,k,r," ascii //weight: 1
        $x_1_8 = "= \"P,:,\\,h,f,r,e,f,\\,c,h,o,y,v,p,\\,v,a,.,p,b,z," ascii //weight: 1
        $x_1_9 = "= \"P,:,\\,h,f,r,e,f,\\,c,h,o,y,v,p,\\,v,a,.,u,g,z,y," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PCM_2147763110_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PCM!MTB"
        threat_id = "2147763110"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 70 ?? 3a ?? 5c ?? 6a ?? 76 ?? 61 ?? 71 ?? 62 ?? 6a ?? 66}  //weight: 1, accuracy: Low
        $x_1_2 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 50 ?? 3a ?? 5c ?? 68 ?? 66 ?? 72 ?? 65 ?? 66}  //weight: 1, accuracy: Low
        $x_1_3 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 50 [0-22] 5c ?? 63 ?? 68 ?? 6f ?? 79 ?? 76 ?? 70 ?? 5c 78 39 30 01 01 76 ?? 61}  //weight: 1, accuracy: Low
        $x_1_4 = "FileNumber = FreeFile" ascii //weight: 1
        $x_1_5 = {23 46 69 6c 65 4e 75 6d 62 65 72 2c 20 53 70 63 28 [0-15] 29}  //weight: 1, accuracy: Low
        $x_1_6 = {49 66 20 28 [0-10] 20 3e 20 36 34 20 41 6e 64 20 [0-10] 20 3c 20 39 31 29 20 4f 72 20 28 [0-10] 20 3e 20 39 36 20 41 6e 64 20 [0-10] 20 3c 20 31 32 33 29}  //weight: 1, accuracy: Low
        $x_1_7 = {4d 69 64 24 28 [0-10] 24 2c 20 [0-10] 2c 20 31 29 20 3d 20 43 68 72 24 28 [0-10] 29}  //weight: 1, accuracy: Low
        $x_1_8 = {3c 20 39 37 20 41 6e 64 20 [0-10] 20 3e 20 38 33 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_9 = {45 6c 73 65 49 66 20 [0-10] 20 3c 20 36 35 20 54 68 65 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PCN_2147763116_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PCN!MTB"
        threat_id = "2147763116"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_2 = ".exec (e456fc10)" ascii //weight: 1
        $x_1_3 = "= Split(d76cab02, \"|\")" ascii //weight: 1
        $x_1_4 = "= StrConv(ec6c75f8, vbUnicode)" ascii //weight: 1
        $x_1_5 = ".Open \"GET\"," ascii //weight: 1
        $x_1_6 = ".d8cb9993 ee6aff0a(0) + \" \" + fa31e116" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PCO_2147764920_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PCO!MTB"
        threat_id = "2147764920"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Send" ascii //weight: 1
        $x_1_2 = "CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_3 = {2e 65 78 65 63 20 28 [0-10] 29}  //weight: 1, accuracy: Low
        $x_1_4 = ".fccdb933 a8a9ba70(0) + \" \" + e9f3423e(\"pdf\")" ascii //weight: 1
        $x_1_5 = {53 70 6c 69 74 28 [0-10] 2c 20 22 7c 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PCO_2147764920_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PCO!MTB"
        threat_id = "2147764920"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_2 = {2e 65 78 65 63 20 28 [0-10] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 53 70 6c 69 74 28 [0-10] 2c 20 22 7c 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = ".jpg\"" ascii //weight: 1
        $x_1_5 = {3d 20 53 74 72 43 6f 6e 76 28 [0-10] 2c 20 76 62 55 6e 69 63 6f 64 65 29}  //weight: 1, accuracy: Low
        $x_1_6 = ".Open \"GET\"," ascii //weight: 1
        $x_1_7 = "(0) + \" \" + " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PW_2147766039_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PW!MTB"
        threat_id = "2147766039"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 ?? ?? ?? ?? ?? 20 2b 20 22 2e 22 20 2b 20 22 73 68 65 6c 6c 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "String = \"ing.FileSystemObject\")" ascii //weight: 1
        $x_1_3 = {28 30 29 20 2b 20 22 76 72 33 32 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c ?? ?? ?? ?? ?? 2e 74 78 74 22 2c 20 22 77 73 63 72 69 70 74 22}  //weight: 1, accuracy: Low
        $x_1_4 = ".Open \"GET\"" ascii //weight: 1
        $x_1_5 = ".responsebody" ascii //weight: 1
        $x_1_6 = "(\"PTTHLMXre\" + \"vres.2LMXSM\")" ascii //weight: 1
        $x_1_7 = {2e 65 78 65 63 28 ?? ?? ?? ?? ?? 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_JAO_2147767172_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.JAO!MTB"
        threat_id = "2147767172"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {52 65 70 6c 61 63 65 28 [0-8] 2c 20 [0-8] 2c 20 22 22 29}  //weight: 3, accuracy: Low
        $x_3_2 = "Split(\"mshta.exe|in.com|in.html\", \"|\")" ascii //weight: 3
        $x_1_3 = {4d 69 64 28 [0-8] 2c 20 [0-15] 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_4 = {4d 69 64 24 28 [0-8] 2c 20 [0-8] 2c 20 31 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_JAO_2147767172_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.JAO!MTB"
        threat_id = "2147767172"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {52 65 70 6c 61 63 65 28 [0-8] 2c 20 [0-8] 2c 20 22 22 29}  //weight: 3, accuracy: Low
        $x_3_2 = "Split(\"mshta.exe|in.com|in.html\", \"|\")" ascii //weight: 3
        $x_2_3 = {28 22 77 69 6e 64 69 72 22 29 20 26 20 [0-8] 20 26 20 22 73 79 73 74 65 6d 33 32 22}  //weight: 2, accuracy: Low
        $x_2_4 = {28 22 77 69 6e 22 20 26 20 22 64 69 72 22 29 20 26 20 [0-8] 20 26 20 22 73 79 73 74 65 22 20 26 20 22 6d 33 32}  //weight: 2, accuracy: Low
        $x_1_5 = {4d 69 64 28 [0-8] 2c 20 [0-8] 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_6 = {4d 69 64 24 28 [0-8] 2c 20 [0-8] 2c 20 31 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_IcedID_ICD_2147767350_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.ICD!MTB"
        threat_id = "2147767350"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Split(\"mshta.exe|in.com|in.html\", \"|\")" ascii //weight: 1
        $x_1_2 = {26 20 4d 69 64 28 [0-16] 2c 20 28 [0-16] 20 2d 20 [0-16] 29 2c 20 31 29 02 00 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 [0-32] 28 [0-21] 29 [0-21] 20 3d 20 52 65 70 6c 61 63 65 28 [0-16] 2c 20 [0-16] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {43 61 6c 6c 20 53 68 65 6c 6c 28 [0-8] 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = {4f 70 65 6e 20 [0-16] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_6 = {4d 69 64 24 28 [0-16] 2c 20 [0-16] 2c 20 31 29 20 3d 20 [0-16] 28 [0-16] 29 02 00 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_7 = "= ActiveDocument.BuiltInDocumentProperties" ascii //weight: 1
        $x_1_8 = {26 20 22 20 22 20 26 20 [0-16] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_9 = {56 42 41 2e 43 68 72 42 28 [0-16] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_EXC_2147769087_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.EXC!MTB"
        threat_id = "2147769087"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 65 78 65 63 20 28 [0-7] 28 [0-6] 29 20 26 20 22 20 22 20 26 20 [0-7] 20 26 20 22 2c 53 68 6f 77 44 69 61 6c 6f 67 41 20 2d 72 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 70 6c 69 74 28 [0-7] 2c 20 [0-6] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-7] 28 [0-7] 29 02 00 27}  //weight: 1, accuracy: Low
        $x_1_4 = "With ActiveDocument.Shapes(1#)" ascii //weight: 1
        $x_1_5 = {3d 20 2e 61 6c 74 65 72 6e 61 74 69 76 65 74 65 78 74 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-7] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 2d 2d 2d 2d 2d 22}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 50 61 74 68 53 65 70 61 72 61 74 6f 72 20 26 20 22 [0-5] 2e 70 64 66 22}  //weight: 1, accuracy: Low
        $x_1_8 = {53 65 74 20 [0-7] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-7] 28 33 29 20 26 20 22 2e 22 20 26 20 [0-7] 28 33 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29}  //weight: 1, accuracy: Low
        $x_1_9 = {6f 53 74 72 65 61 6d 2e 53 61 76 65 54 6f 46 69 6c 65 20 [0-7] 2c 20 32 02 00 6f 53 74 72 65 61 6d 2e 43 6c 6f 73 65 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RV_2147769581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RV!MTB"
        threat_id = "2147769581"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\programdata\\RpLBT.pdf" ascii //weight: 1
        $x_1_2 = "Split(ActiveDocument.Shapes(1#).Title, ZQfRv)" ascii //weight: 1
        $x_1_3 = "Len(WrqvR)" ascii //weight: 1
        $x_1_4 = "CreateObject(fvczP(3) & \".\" & fvczP(3) & \"request.5.1\")" ascii //weight: 1
        $x_1_5 = "Open \"GET\", TwrtQ(Gfhzw), False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_EXY_2147769626_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.EXY!MTB"
        threat_id = "2147769626"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 65 78 65 63 20 28 [0-7] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4d 69 64 24 28 [0-6] 2c 20 [0-6] 2c 20 [0-6] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-6] 28 [0-6] 29 02 00 27}  //weight: 1, accuracy: Low
        $x_1_3 = {53 65 74 20 [0-7] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-7] 28 33 29 20 26 20 22 2e 22 20 26 20 [0-7] 28 33 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {6f 53 74 72 65 61 6d 2e 53 61 76 65 54 6f 46 69 6c 65 20 [0-7] 2c 20 32 02 00 6f 53 74 72 65 61 6d 2e 43 6c 6f 73 65 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 [0-6] 28 [0-6] 29 2c 20 46 61 6c 73 65 02 00 27}  //weight: 1, accuracy: Low
        $x_1_6 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-6] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 2d 2d 2d 2d 2d 22 02 00 27}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-6] 2e 70 64 66 22}  //weight: 1, accuracy: Low
        $x_1_8 = {53 75 62 20 [0-6] 28 [0-6] 2c 20 4f 70 74 69 6f 6e 61 6c 20 42 79 56 61 6c 20 [0-6] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 73 79 73 74 65 6d 6f 62 6a 65 63 74 22 29 02 00 27}  //weight: 1, accuracy: Low
        $x_1_9 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 02 00 27}  //weight: 1, accuracy: Low
        $x_1_10 = {26 20 22 20 22 20 26 20 [0-5] 20 26 20 [0-5] 28 22 72 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVA_2147769627_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVA!MTB"
        threat_id = "2147769627"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\programdata\\Pgroh.pdf" ascii //weight: 1
        $x_1_2 = "Split(ActiveDocument.Shapes(1#).Title, obdVs)" ascii //weight: 1
        $x_1_3 = "CreateObject(aSshT(3) & \".\" & aSshT(3) & \"request.5.1\")" ascii //weight: 1
        $x_1_4 = "Open \"GET\", vvxDY(SiSpZ), False" ascii //weight: 1
        $x_1_5 = "CreateObject(\"ADODB.Stream\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_EXZ_2147769709_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.EXZ!MTB"
        threat_id = "2147769709"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 65 78 65 63 20 28 [0-7] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4d 69 64 24 28 [0-6] 2c 20 [0-6] 2c 20 [0-6] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-6] 28 [0-6] 29 02 00 27}  //weight: 1, accuracy: Low
        $x_1_3 = {53 65 74 20 [0-7] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-7] 28 33 29 20 26 20 22 2e 22 20 26 20 [0-7] 28 33 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 53 70 6c 69 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 31 23 29 2e 54 69 74 6c 65 2c 20 [0-5] 29 02 00 27}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 [0-6] 28 [0-6] 29 2c 20 46 61 6c 73 65 02 00 27}  //weight: 1, accuracy: Low
        $x_1_6 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-6] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 2d 2d 2d 2d 2d 22 02 00 27}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-6] 2e 70 64 66 22}  //weight: 1, accuracy: Low
        $x_1_8 = {53 75 62 20 [0-6] 28 [0-6] 2c 20 4f 70 74 69 6f 6e 61 6c 20 42 79 56 61 6c 20 [0-6] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 73 79 73 74 65 6d 6f 62 6a 65 63 74 22 29 02 00 27}  //weight: 1, accuracy: Low
        $x_1_9 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 02 00 27}  //weight: 1, accuracy: Low
        $x_1_10 = "& \" \" &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_EXZ_2147769709_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.EXZ!MTB"
        threat_id = "2147769709"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 65 78 65 63 20 28 [0-7] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4d 69 64 24 28 [0-6] 2c 20 [0-6] 2c 20 [0-6] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-6] 28 [0-6] 29 02 00 27}  //weight: 1, accuracy: Low
        $x_1_3 = {53 65 74 20 [0-7] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-7] 28 33 29 20 26 20 22 2e 22 20 26 20 [0-7] 28 33 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 28 [0-5] 29 02 00 2e 43 6c 6f 73 65 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 [0-6] 28 [0-6] 29 2c 20 46 61 6c 73 65 02 00 27}  //weight: 1, accuracy: Low
        $x_1_6 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-6] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 2d 2d 2d 2d 2d 22 02 00 27}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-6] 2e 70 64 66 22}  //weight: 1, accuracy: Low
        $x_1_8 = {26 20 22 20 22 20 26 20 [0-6] 20 26 20 22 2c 53 68 6f 77 44 69 61 6c 6f 67 41 20 2d 72 22}  //weight: 1, accuracy: Low
        $x_1_9 = {53 75 62 20 [0-6] 28 [0-6] 2c 20 4f 70 74 69 6f 6e 61 6c 20 42 79 56 61 6c 20 [0-6] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 73 79 73 74 65 6d 6f 62 6a 65 63 74 22 29 02 00 27}  //weight: 1, accuracy: Low
        $x_1_10 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 02 00 27}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_FAA_2147770175_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.FAA!MTB"
        threat_id = "2147770175"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= ActiveDocument.BuiltInDocumentProperties(\"subject\") & \"1-8455-00A0C91\"" ascii //weight: 1
        $x_1_2 = {47 65 74 4f 62 6a 65 63 74 28 73 75 62 6a 65 63 74 20 26 20 22 46 33 38 38 30 22 29 2e 4e 61 76 69 67 61 74 65 20 74 69 74 6c 65 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = "title = ActiveDocument.BuiltInDocumentProperties(\"title\")" ascii //weight: 1
        $x_1_4 = {50 72 69 6e 74 20 23 31 2c 20 [0-32] 43 6c 6f 73 65 20 23 31}  //weight: 1, accuracy: Low
        $x_1_5 = {28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 74 65 78 74 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_FAA_2147770175_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.FAA!MTB"
        threat_id = "2147770175"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 53 75 62 20 [0-6] 28 [0-6] 2c 20 [0-6] 29 02 00 27}  //weight: 1, accuracy: Low
        $x_1_2 = {4f 70 65 6e 20 [0-6] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 [0-4] 50 72 69 6e 74 20 23 31 2c 20 [0-16] 43 6c 6f 73 65 20 23 [0-3] 45 6e 64 20 53 75 62 02 00 46 75 6e 63 74 69 6f 6e 20 [0-6] 28 [0-6] 2c 20 [0-6] 2c 20 [0-6] 29 02 00 27}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-6] 28 [0-6] 29 2c 20 [0-6] 2c 20 [0-6] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 53 75 62 20 [0-6] 28 29 [0-16] 20 3d}  //weight: 1, accuracy: Low
        $x_1_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 72 75 6e 20 28 [0-6] 20 26 20 22 20 22 20 26 20 [0-6] 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = {57 69 74 68 20 2e 47 65 74 45 6e 63 6f 64 65 64 43 6f 6e 74 65 6e 74 53 74 72 65 61 6d 02 00 2e 57 72 69 74 65 54 65 78 74 20 [0-16] 2e 46 6c 75 73 68 02 00 45 6e 64 20 57 69 74 68 02 00 57 69 74 68 20 2e 47 65 74 44 65 63 6f 64 65 64 43 6f 6e 74 65 6e 74 53 74 72 65 61 6d}  //weight: 1, accuracy: Low
        $x_1_6 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-16] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_7 = ".ContentTransferEncoding = \"base64\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVB_2147770287_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVB!MTB"
        threat_id = "2147770287"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\programdata\\WLyPT.pdf" ascii //weight: 1
        $x_1_2 = "CreateObject(gfLRK(3) & \".\" & gfLRK(3) & \"request.5.1\")" ascii //weight: 1
        $x_1_3 = "PcCrB.Open \"GET\", neXNa, False" ascii //weight: 1
        $x_1_4 = "Len(HNgNu) To 1 Step -1" ascii //weight: 1
        $x_1_5 = "CreateObject(\"adodb.stream\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_FAB_2147770347_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.FAB!MTB"
        threat_id = "2147770347"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= StrReverse(UserForm1.TextBox1)" ascii //weight: 1
        $x_1_2 = "With removeCollectionRequest.Documents.Add.VBProject.VBComponents(\"ThisDocument\").CodeModule" ascii //weight: 1
        $x_1_3 = "= \"HKEY\" & constW & \"USER\\Soft\" & bufferDatabase & \"ice\\\"" ascii //weight: 1
        $x_1_4 = {3d 20 52 65 70 6c 61 63 65 28 22 69 74 79 5c 41 63 63 65 73 73 31 4f 4d 22 2c 20 22 31 22 2c 20 22 56 42 22 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_FAB_2147770347_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.FAB!MTB"
        threat_id = "2147770347"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 20 22 20 26 20 [0-6] 20 26 20 22 2c 53 68 6f 77 44 69 61 22 20 2b 20 22 6c 6f 67 41 20 2d 72 22}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-6] 2e 70 64 66 22}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 4d 69 64 24 28 [0-6] 2c 20 [0-6] 2c 20 [0-6] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 65 78 65 63 20 28 [0-6] 29 02 00 27 20}  //weight: 1, accuracy: Low
        $x_1_5 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-6] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 [0-8] 22 02 00 27 20}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 53 70 6c 69 74 28 2e 53 68 61 70 65 73 28 31 29 2e 54 69 74 6c 65 2c 20 [0-6] 29}  //weight: 1, accuracy: Low
        $x_1_7 = {53 65 74 20 [0-6] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-6] 28 [0-3] 29 20 26 20 22 2e 22 20 26 20 [0-6] 28 [0-3] 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29}  //weight: 1, accuracy: Low
        $x_1_8 = {2e 53 65 6e 64 02 00 27 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RD_2147770348_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RD!MTB"
        threat_id = "2147770348"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 20 ?? ?? ?? ?? ?? 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 ?? ?? ?? ?? ?? 28 33 29 20 26 20 22 2e 22 20 26 20 ?? ?? ?? ?? ?? 28 33 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 ?? ?? ?? ?? ?? 28 ?? ?? ?? ?? ?? 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = "CreateObject(\"adodb.stream\")" ascii //weight: 1
        $x_1_4 = ".responsebody" ascii //weight: 1
        $x_1_5 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 [0-7] 2c 20 32}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 65 78 65 63 20 28 ?? ?? ?? ?? ?? 29}  //weight: 1, accuracy: Low
        $x_1_7 = {53 70 6c 69 74 28 2e 53 68 61 70 65 73 28 31 29 2e 54 69 74 6c 65 2c 20 ?? ?? ?? ?? ?? 29}  //weight: 1, accuracy: Low
        $x_1_8 = {70 72 6f 67 72 61 6d 64 61 74 61 5c ?? ?? ?? ?? ?? 2e 70 64 66}  //weight: 1, accuracy: Low
        $x_1_9 = {4c 65 6e 28 ?? ?? ?? ?? ?? 29 20 54 6f 20 31 20 53 74 65 70 20 2d 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanDownloader_O97M_IcedID_FAC_2147770540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.FAC!MTB"
        threat_id = "2147770540"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "(.Shapes(1).Title)" ascii //weight: 1
        $x_1_2 = {3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-5] 2e 70 64 66 22}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 4d 69 64 24 28 [0-5] 2c 20 [0-5] 2c 20 [0-5] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-5] 28 [0-5] 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 65 74 20 [0-5] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-5] 28 33 29 20 26 20 22 2e 22 20 26 20 [0-5] 28 33 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {26 20 22 20 22 20 26 20 4f 46 6c 70 43 20 26 20 22 2c 53 68 6f 77 44 69 61 22 20 2b 20 22 6c 6f 67 41 20 2d 72 22 [0-8] 28 [0-6] 29 2e 65 78 65 63 20 28 [0-6] 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 57 72 69 74 65 20 [0-5] 2e 72 65 73 70 6f 6e 73 65 62 6f 64 79 [0-8] 2e 53 61 76 65 54 6f 46 69 6c 65 20 4f 46 6c 70 43 2c 20 [0-16] 2e 43 6c 6f 73 65 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVC_2147771214_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVC!MTB"
        threat_id = "2147771214"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-5] 2e 70 64 66}  //weight: 1, accuracy: Low
        $x_1_2 = {4f 70 65 6e 20 22 47 45 54 22 2c 20 [0-5] 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = "XOdFo(.Shapes(1).Title)" ascii //weight: 1
        $x_1_4 = {4c 65 6e 28 [0-5] 29 20 54 6f 20 31 20 53 74 65 70 20 2d 31}  //weight: 1, accuracy: Low
        $x_1_5 = "CreateObject(\"adodb.stream\")" ascii //weight: 1
        $x_1_6 = "CreateObject(AjgpH(3) & \".\" & AjgpH(3) & \"request.5.1\")" ascii //weight: 1
        $x_1_7 = {69 64 41 6d 47 28 [0-5] 29 2e 65 78 65 63}  //weight: 1, accuracy: Low
        $x_1_8 = {4e 43 6c 45 44 28 [0-5] 29 20 26 20 22 20 22 20 26 20 73 42 6d 6e 50 20 26 20 22 2c 53 68 6f 77 44 69 61 22 20 2b 20 22 6c 6f 67 41 20 2d 72 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_FAD_2147771281_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.FAD!MTB"
        threat_id = "2147771281"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 20 22 20 26 20 [0-6] 20 26 20 22 2c 53 68 6f 77 44 69 61 22 20 2b 20 22 6c 6f 67 41 20 2d 72 22 [0-8] 28 [0-6] 29 2e 65 78 65 63 20 28 [0-6] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4d 69 64 24 28 [0-6] 2c 20 [0-6] 2c 20 [0-6] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-6] 28 [0-6] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-6] 2e 70 64 66 22 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {28 2e 53 68 61 70 65 73 28 31 29 2e 54 69 74 6c 65 29 02 00 45 6e 64 20 57 69 74 68}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 53 70 6c 69 74 28 [0-6] 2c 20 [0-6] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-6] 28 [0-6] 29 02 00 57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74}  //weight: 1, accuracy: Low
        $x_1_6 = {53 65 74 20 [0-6] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-6] 28 33 29 20 26 20 22 2e 22 20 26 20 [0-6] 28 33 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29}  //weight: 1, accuracy: Low
        $x_1_7 = {2e 57 72 69 74 65 20 [0-6] 2e 72 65 73 70 6f 6e 73 65 62 6f 64 79 [0-8] 2e 53 61 76 65 54 6f 46 69 6c 65 20 [0-6] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_FAE_2147771425_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.FAE!MTB"
        threat_id = "2147771425"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 56 42 41 2e 53 70 6c 69 74 28 [0-6] 2c 20 [0-6] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-6] 28 [0-6] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 [0-6] 29 2e 6e 61 6d 65 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-6] 28 [0-6] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 4d 69 64 24 28 [0-6] 2c 20 [0-6] 2c 20 [0-6] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-6] 28 [0-6] 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 65 74 20 [0-6] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-6] 28 [0-6] 29 20 26 20 22 2e 22 20 26 20 [0-6] 28 [0-6] 29 20 26 20 [0-6] 28 22 31 2e 35 2e 74 73 65 75 71 65 72 22 29 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 [0-6] 2c 20 46 61 6c 73 65 [0-8] 2e 53 65 6e 64}  //weight: 1, accuracy: Low
        $x_1_6 = {26 20 22 20 22 20 26 20 [0-6] 20 26 20 [0-6] 28 [0-6] 28 [0-6] 29 29 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 20 54 72 69 6d 28 2e 65 78 65 63 28 [0-6] 29 29 02 00 45 6e 64 20 57 69 74 68}  //weight: 1, accuracy: Low
        $x_1_8 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-6] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 5f 5f 5f 22 02 00 46 75 6e 63 74 69 6f 6e 20 [0-6] 28 [0-6] 2c 20 [0-6] 29}  //weight: 1, accuracy: Low
        $x_1_9 = {20 3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-16] 2e 70 64 66 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_FAF_2147771433_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.FAF!MTB"
        threat_id = "2147771433"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 20 22 20 26 20 [0-6] 20 26 20 [0-6] 28 22 72 2d 20 41 67 6f 6c 61 22 20 26 20 22 [0-6] 2c 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 2e 72 75 6e 28 [0-6] 29 02 00 45 6e 64 20 57 69 74 68}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 [0-6] 29 2e 6e 61 6d 65 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-6] 28 [0-6] 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 4d 69 64 24 28 [0-6] 2c 20 [0-6] 2c 20 [0-6] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-6] 28 [0-6] 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 [0-6] 2c 20 46 61 6c 73 65 [0-8] 2e 53 65 6e 64}  //weight: 1, accuracy: Low
        $x_1_6 = {20 3d 20 53 70 6c 69 74 28 [0-6] 2c 20 [0-6] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_7 = {53 65 74 20 [0-6] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-6] 28 [0-6] 29 20 26 20 22 2e 22 20 26 20 [0-6] 28 [0-6] 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29}  //weight: 1, accuracy: Low
        $x_1_8 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-6] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 5f 5f 5f 22 02 00 46 75 6e 63 74 69 6f 6e 20 [0-6] 28 [0-6] 2c 20 [0-6] 29}  //weight: 1, accuracy: Low
        $x_1_9 = {20 3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-16] 2e 70 64 66 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_CRO_2147771739_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.CRO!MTB"
        threat_id = "2147771739"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-6] 29 2e 65 78 65 63 20 28 [0-6] 20 26 20 22 20 22 20 26 20 [0-6] 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-6] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 68 22}  //weight: 1, accuracy: Low
        $x_1_3 = " = \"\"" ascii //weight: 1
        $x_1_4 = {20 3d 20 43 68 72 28 [0-7] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {53 75 62 20 [0-6] 28 [0-6] 2c 20 [0-6] 29 02 00 27 20}  //weight: 1, accuracy: Low
        $x_1_6 = {20 3d 20 56 42 41 2e 63 6c 6e 67 28 [0-6] 28 [0-6] 29 20 26 20 [0-6] 20 26 20 [0-6] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 [0-6] 28 [0-6] 29 02 00 27 20}  //weight: 1, accuracy: Low
        $x_1_7 = {4f 70 65 6e 20 [0-6] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 [0-4] 50 72 69 6e 74 20 23 31 2c 20 [0-16] 43 6c 6f 73 65 20 23 [0-4] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_8 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-6] 28 [0-6] 29 2c 20 [0-6] 2c 20 [0-6] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVD_2147773079_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVD!MTB"
        threat_id = "2147773079"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Open aeRPfj For Output As #1" ascii //weight: 1
        $x_1_2 = "ajsdRJ(Split(amE4FZ, \",\"))" ascii //weight: 1
        $x_1_3 = "Print #1, ajxPi" ascii //weight: 1
        $x_1_4 = "aM5wU.ShellExecute aICFl5, azeT8, \" \", SW_SHOWNORMAL" ascii //weight: 1
        $x_1_5 = "acu4W8 & Chr(an6Aer(af6yrN) Xor 4)" ascii //weight: 1
        $x_1_6 = "ah2Y9B = ActiveDocument.Content" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_VIS_2147773250_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.VIS!MTB"
        threat_id = "2147773250"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \"\\m1.xsl" ascii //weight: 1
        $x_1_2 = "& \"\\m1.com" ascii //weight: 1
        $x_1_3 = "run a38Ub5 & aRlMyx(\"comments\") & amE2ak & aQxo3B & amE2ak" ascii //weight: 1
        $x_1_4 = "FileCopy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_VIS_2147773250_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.VIS!MTB"
        threat_id = "2147773250"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Split(ActiveDocument.Range.Text, \"x\")" ascii //weight: 1
        $x_1_2 = {26 20 22 6d 64 61 74 61 5c [0-32] 2e 68 22 20 26}  //weight: 1, accuracy: Low
        $x_1_3 = {53 68 65 6c 6c [0-255] 28 22 65 78 70 6c 6f 72 65 72 20 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {50 72 69 6e 74 20 23 31 2c 20 [0-32] 43 6c 6f 73 65 20 23 31 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = "out & Chr(arr(cnt) Xor 100)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_VIS_2147773250_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.VIS!MTB"
        threat_id = "2147773250"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Optional currIntegerTrust = \"c:\\program\", Optional WSetPointer = \"a\")" ascii //weight: 1
        $x_1_2 = "& \"data\\arrValTrust.ht\" &" ascii //weight: 1
        $x_1_3 = "out & Chr(arr(cnt) Xor 10)" ascii //weight: 1
        $x_1_4 = "Shell(headerInd(\"c:\\\\windows\\\\explorer \")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_VIS_2147773250_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.VIS!MTB"
        threat_id = "2147773250"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ListBox1.AddItem (\"://dettagl.net/\" + MemSelect())" ascii //weight: 1
        $x_1_2 = "VarDatabase.Write" ascii //weight: 1
        $x_1_3 = "VarDatabase.SaveToFile" ascii //weight: 1
        $x_1_4 = "Shell% (RepoConvertRight + \" \" &" ascii //weight: 1
        $x_1_5 = "C:\\users\\Public\\\" + MemSelect()" ascii //weight: 1
        $x_1_6 = "= CStr(Int(999999 * Rnd) + 1) + \".jpg\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_VIS_2147773250_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.VIS!MTB"
        threat_id = "2147773250"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CStr(Int(999999 * Rnd) + 1) + \".jpg\"" ascii //weight: 1
        $x_1_2 = "ListBox1.AddItem (\"://condizioni.net/\" + ResponseLenSelect())" ascii //weight: 1
        $x_1_3 = "C:\\users\\Public\\\" + ResponseLenSelect()" ascii //weight: 1
        $x_1_4 = "Buffer64Pointer.Write" ascii //weight: 1
        $x_1_5 = "Buffer64Pointer.SaveToFile" ascii //weight: 1
        $x_1_6 = "Shell% (CounterProcConst + \" \" &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_QNH_2147773372_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.QNH!MTB"
        threat_id = "2147773372"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Function aQOBS(awVsJe As Variant)" ascii //weight: 1
        $x_1_2 = "axja2 = \"\"" ascii //weight: 1
        $x_1_3 = "a0FWL = ActiveDocument.Content" ascii //weight: 1
        $x_1_4 = {53 68 65 6c 6c 20 61 31 74 35 6e 20 26 20 22 20 22 20 26 20 61 51 32 6e 48 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = " = Split(av35x," ascii //weight: 1
        $x_1_6 = "Open aRdcZL For Output As #1" ascii //weight: 1
        $x_1_7 = "Print #1, aWrayg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_BIK_2147773632_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.BIK!MTB"
        threat_id = "2147773632"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Split(aqMXZ9(frm.paths.text), \"|\")" ascii //weight: 1
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 28 [0-10] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 61 76 56 66 65 62 22 2c 20 [0-10] 20 26 20 22 20 22 20 26 20 [0-10] 20 26 20 22 6d 61 74 20 3a 20 22 22 22 20 26 20 [0-10] 20 26}  //weight: 1, accuracy: Low
        $x_1_4 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVE_2147773643_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVE!MTB"
        threat_id = "2147773643"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "10.23.31.3.0.29.10.29" ascii //weight: 1
        $x_1_2 = "CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_3 = {4c 65 6e 28 61 [0-5] 29 20 3e 20 30 20 54 68 65 6e 20 61 4e 78 43 4d 47 20 3d 20 53 70 6c 69 74 28 61 [0-5] 2c 20 22 2e 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {43 61 6c 6c 20 61 42 30 6e 76 64 28 61 [0-5] 2c 20 61 68 72 55 38 56 28 61 [0-5] 29 29}  //weight: 1, accuracy: Low
        $x_1_5 = {4d 69 64 28 61 [0-5] 2c 20 61 [0-5] 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_6 = {53 68 65 6c 6c 20 61 [0-5] 20 26 20 22 20 22 20 26 20}  //weight: 1, accuracy: Low
        $x_1_7 = "myf.text1.value" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVF_2147773829_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVF!MTB"
        threat_id = "2147773829"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "1171234104123496123412412341271234981234117123498" ascii //weight: 1
        $x_1_2 = "Shell \"C:\\Windows\\explorer.exe \" & " ascii //weight: 1
        $x_1_3 = {61 38 58 77 74 4e 20 3d 20 54 72 69 6d 28 22 22 20 26 20 61 [0-5] 20 58 6f 72 20 61 [0-5] 29}  //weight: 1, accuracy: Low
        $x_1_4 = "CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_5 = {43 61 6c 6c 20 61 6a 43 48 6e 28 61 [0-5] 2c 20 61 37 64 77 4b 28 61 [0-5] 29 29}  //weight: 1, accuracy: Low
        $x_1_6 = {43 68 72 28 22 22 20 26 20 61 [0-5] 20 26 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_7 = {4d 69 64 28 61 [0-5] 2c 20 61 [0-5] 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_8 = {61 43 59 46 6d 32 28 61 38 58 77 74 4e 28 61 [0-5] 28 61 [0-5] 29 2c 20 31 36 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVG_2147774310_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVG!MTB"
        threat_id = "2147774310"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "30.3.11.23.20.9.30.9" ascii //weight: 1
        $x_1_2 = "Shell aXDpx & \" \" & aHYEC" ascii //weight: 1
        $x_1_3 = "Mid(a9WIDx, aL4cf, 1)" ascii //weight: 1
        $x_1_4 = "Split(aZvjdU, \".\")" ascii //weight: 1
        $x_1_5 = "Open aAykB3 For Output As #1" ascii //weight: 1
        $x_1_6 = "Print #1, aFl2P" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_SMK_2147776088_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.SMK!MTB"
        threat_id = "2147776088"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "anUHD = Split(a5mtiD(frm.paths.text), \"|\")" ascii //weight: 1
        $x_1_2 = "aXLZQ = Trim(arKS7 & \"t : \" & a0xVW & atboU & a0xVW)" ascii //weight: 1
        $x_1_3 = "Call a3alM.ShellExecute(aa3MIF, aXLZQ, \" \", SW_SHOWNORMAL)" ascii //weight: 1
        $x_1_4 = "Set arunF = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_5 = "Call arunF.CopyFile(as46g, auHMZa, 1)" ascii //weight: 1
        $x_1_6 = "Open ay6rsq For Output As #1" ascii //weight: 1
        $x_1_7 = "With CreateObject(\"Microsoft.XMLDOM\").createElement(\"b64\")" ascii //weight: 1
        $x_1_8 = ".DataType = \"bin.base64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PGI_2147777110_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PGI!MTB"
        threat_id = "2147777110"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Trim(aJrRwy & \"t : \" & arSxw & aVToK0 & arSxw)" ascii //weight: 1
        $x_1_2 = "Call azKFt.ShellExecute(a5mre, agrp0, \" \", SW_SHOWNORMAL)" ascii //weight: 1
        $x_1_3 = "a54XgN = Split(aE73Bi(frm.paths.text), \"|\")" ascii //weight: 1
        $x_1_4 = "Call aF3xO.CopyFile(alVXYx, ay3zi, 1)" ascii //weight: 1
        $x_1_5 = "aQJNts = StrConv(b, vbUnicode)" ascii //weight: 1
        $x_1_6 = "aQYND = aQYND & \"\" & Mid(aFwCi, ag5tUp, 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_ICE_2147777176_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.ICE!MTB"
        threat_id = "2147777176"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 22 20 26 20 4d 69 64 28 [0-7] 2c 20 [0-7] 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e 20 [0-7] 28 62 36 34 29}  //weight: 1, accuracy: Low
        $x_1_3 = "With CreateObject(\"Microsoft.XMLDOM\").createElement(\"b64\")" ascii //weight: 1
        $x_1_4 = ".DataType = \"bin.base64\"" ascii //weight: 1
        $x_1_5 = ".text = b64" ascii //weight: 1
        $x_1_6 = "b = .nodeTypedValue" ascii //weight: 1
        $x_1_7 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_8 = {43 61 6c 6c 20 [0-7] 2e 43 6f 70 79 46 69 6c 65 28 [0-7] 2c 20 [0-7] 2c 20 31 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_9 = {4f 70 65 6e 20 [0-7] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_10 = "Print #1," ascii //weight: 1
        $x_1_11 = {43 6c 6f 73 65 20 23 31 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_12 = {3d 20 53 70 6c 69 74 28 [0-7] 28 66 72 6d 2e 70 61 74 68 73 2e 74 65 78 74 29 2c 20 22 7c 22 29}  //weight: 1, accuracy: Low
        $x_1_13 = {3d 20 53 70 6c 69 74 28 [0-7] 2c 20 22 2c 22 29}  //weight: 1, accuracy: Low
        $x_1_14 = "(frm.text1.value)" ascii //weight: 1
        $x_1_15 = "= Chr(34)" ascii //weight: 1
        $x_1_16 = {44 69 6d 20 [0-7] 20 41 73 20 4e 65 77 20 53 68 65 6c 6c 33 32 2e 53 68 65 6c 6c}  //weight: 1, accuracy: Low
        $x_1_17 = {43 61 6c 6c 20 [0-7] 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 [0-7] 2c 20 [0-7] 2c 20 22 20 22 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_AIC_2147778197_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.AIC!MTB"
        threat_id = "2147778197"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"c:\\users\\public\\main.hta\"" ascii //weight: 1
        $x_1_2 = ".exec frm.CommandButton1.Tag & \" c:\\users\\public\\main.hta\"" ascii //weight: 1
        $x_1_3 = "Call frm.CommandButton1_Click" ascii //weight: 1
        $x_1_4 = "= \"<div id='content'>fTtlc29" ascii //weight: 1
        $x_1_5 = {43 6c 6f 73 65 20 23 31 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_6 = "Print #1," ascii //weight: 1
        $x_1_7 = "for(x=0;x<L;x++" ascii //weight: 1
        $x_1_8 = "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA" ascii //weight: 1
        $x_1_9 = "split('').reverse().join('');" ascii //weight: 1
        $x_1_10 = "Timeout = 60000" ascii //weight: 1
        $x_1_11 = "Sub autoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_AID_2147778268_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.AID!MTB"
        threat_id = "2147778268"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Sub CommandButton1_Click()" ascii //weight: 1
        $x_1_2 = ".exec frm.cmdButton1.Tag & \" \" & frm.cmdButton1.caption" ascii //weight: 1
        $x_1_3 = "= frm.cmdButton1.caption" ascii //weight: 1
        $x_1_4 = "Call frm.CommandButton1_Click" ascii //weight: 1
        $x_1_5 = "= \"<div id='content'>dmFyI" ascii //weight: 1
        $x_1_6 = ".close</script>" ascii //weight: 1
        $x_1_7 = "<div id='table'>0123456789+/</div><script language='javascript'>" ascii //weight: 1
        $x_1_8 = "var w=String.fromCharCode" ascii //weight: 1
        $x_1_9 = {43 6c 6f 73 65 20 23 31 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_10 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_11 = "Print #1," ascii //weight: 1
        $x_1_12 = "for(x=0;x<L;x++" ascii //weight: 1
        $x_1_13 = "split('').reverse().join('');" ascii //weight: 1
        $x_1_14 = "Timeout = 60000" ascii //weight: 1
        $x_1_15 = "Sub autoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_AIE_2147778276_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.AIE!MTB"
        threat_id = "2147778276"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Sub CommandButton1_Click()" ascii //weight: 1
        $x_1_2 = ".exec frm.cmdButton1.Tag & \" \" & frm.cmdButton1.caption" ascii //weight: 1
        $x_1_3 = "= frm.cmdButton1.caption" ascii //weight: 1
        $x_1_4 = "Call frm.CommandButton1_Click" ascii //weight: 1
        $x_1_5 = "= \"<div id='content'>dmFyI" ascii //weight: 1
        $x_1_6 = ".close</script>" ascii //weight: 1
        $x_1_7 = "<div id='table'>0123456789+/</div><scri" ascii //weight: 1
        $x_1_8 = "var w=String.fromCha" ascii //weight: 1
        $x_1_9 = {43 6c 6f 73 65 20 23 31 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_10 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_11 = "Print #1," ascii //weight: 1
        $x_1_12 = "(x=0;x<L;x++)" ascii //weight: 1
        $x_1_13 = "split('').reverse().join('');" ascii //weight: 1
        $x_1_14 = "Timeout = 60000" ascii //weight: 1
        $x_1_15 = "Sub autoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PNK_2147778301_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PNK!MTB"
        threat_id = "2147778301"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"c:\\users\\public\\main.hta\"" ascii //weight: 1
        $x_1_2 = ".exec frm.CommandButton1.Tag & \" c:\\users\\public\\main.hta\"" ascii //weight: 1
        $x_1_3 = "Call frm.CommandButton1_Click" ascii //weight: 1
        $x_1_4 = "= \"<div id='content'>fTtlc29" ascii //weight: 1
        $x_1_5 = ".reverse().join('')" ascii //weight: 1
        $x_1_6 = ".Timeout = 60000" ascii //weight: 1
        $x_1_7 = "DpjIDIzcnZzZ2VyIihudXIuKSJsbGVocy50cGlyY3N3Iih0Y2VqYk9YZXZpdGNBIHdlbg" ascii //weight: 1
        $x_1_8 = "mMgMjNydnNnZXIiKG51ci4pImxsZWhzLnRwaXJjc3ciKHRjZWpiT1hldml0Y0Egd2Vu" ascii //weight: 1
        $x_1_9 = "Sub autoopen()" ascii //weight: 1
        $x_1_10 = "split('|');var" ascii //weight: 1
        $x_1_11 = "Print #1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PNS_2147778302_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PNS!MTB"
        threat_id = "2147778302"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"c:\\users\\public\\main.hta\"" ascii //weight: 1
        $x_1_2 = ".exec frm.CommandButton1.Tag & \" c:\\users\\public\\main.hta\"" ascii //weight: 1
        $x_1_3 = "Call frm.CommandButton1_Click" ascii //weight: 1
        $x_1_4 = "= \"<div id='content'>fTtlc29" ascii //weight: 1
        $x_1_5 = ".reverse().join('')" ascii //weight: 1
        $x_1_6 = ".Timeout = 60" ascii //weight: 1
        $x_1_7 = "Wx7eXJ0OykidGNlamJvbWV0c3lzZWxpZi5nbml0cGlyY3MiKHRj" ascii //weight: 1
        $x_1_8 = "9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA" ascii //weight: 1
        $x_1_9 = "Sub autoopen()" ascii //weight: 1
        $x_1_10 = "split('|');var" ascii //weight: 1
        $x_1_11 = "Print #1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PNL_2147778360_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PNL!MTB"
        threat_id = "2147778360"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".exec frm.cmdButton1.Tag & \" \" & frm.cmdButton1.caption" ascii //weight: 1
        $x_1_2 = "Call frm.CommandButton1_Click" ascii //weight: 1
        $x_1_3 = "= frm.cmdButton1.caption" ascii //weight: 1
        $x_1_4 = ".reverse().join('')" ascii //weight: 1
        $x_1_5 = ".Timeout = 60000" ascii //weight: 1
        $x_1_6 = "XJ0OykidGNlamJvbWV0c3lzZWxpZi5nbml0cGlyY3MiKHRjZ" ascii //weight: 1
        $x_1_7 = "Sub autoopen()" ascii //weight: 1
        $x_1_8 = "split('|');var" ascii //weight: 1
        $x_1_9 = "Print #1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVJ_2147778367_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVJ!MTB"
        threat_id = "2147778367"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 20 28 [0-15] 20 26 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 28 22 35 63}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 4f 70 65 6e 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 28 22 34 37 34 35 35 34 22 29 2c 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 28 22 36 38 37 34 37 34 37 30 33 61 [0-120] 36 35 37 38 36 35 22 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 32 29 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 63 72 65 65 6e 55 70 64 61 74 69 6e 67 20 3d 20 54 72 75 65 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: High
        $x_1_5 = {57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 0d 0a 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 63 72 65 65 6e 55 70 64 61 74 69 6e 67 20 3d 20 46 61 6c 73 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVJ_2147778367_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVJ!MTB"
        threat_id = "2147778367"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Split(ActiveDocument.BuiltInDocumentProperties(\"title\"), \"|||\")" ascii //weight: 1
        $x_1_2 = "Open requestData(1) For Output As #1" ascii //weight: 1
        $x_1_3 = "Print #1, ActiveDocument.Range.Text" ascii //weight: 1
        $x_1_4 = {53 75 62 20 6d 61 69 6e 28 29 0d 0a 6c 69 6e 6b 47 65 6e 65 72 69 63 52 65 70 6f}  //weight: 1, accuracy: High
        $x_1_5 = {43 61 6c 6c 20 47 65 74 4f 62 6a 65 63 74 28 72 65 71 75 65 73 74 44 61 74 61 28 32 29 29 2e 4e 61 76 69 67 61 74 65 28 72 65 71 75 65 73 74 44 61 74 61 28 31 29 29 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: High
        $x_1_6 = {43 61 6c 6c 20 67 65 6e 65 72 69 63 50 74 72 54 65 78 74 62 6f 78 0d 0a 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVK_2147778368_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVK!MTB"
        threat_id = "2147778368"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 28 22 35 37 35 33 36 33 37 32 36 39 37 30 37 34 32 65 35 33 36 38 22 29 20 26 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 28 22 36 35 36 63 36 63 22 29 29 2e 52 75 6e 20 63 6d 64 4c 69 6e 65 2c 20 30}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 47 65 74 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 28 22 35 37 36 39 36 65 33 33 33 32 35 66 35 30 37 32 36 66 36 33 36 35 37 33 37 33 35 33 22 29 20 26 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 28 22 37 34 36 31 37 32 37 34 37 35 37 30 22 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 32 29 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {22 36 33 36 31 22 29 20 26 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 28 22 36 63 36 33 32 65 36 35 37 38 36 35 22}  //weight: 1, accuracy: Low
        $x_1_5 = "AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVK_2147778368_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVK!MTB"
        threat_id = "2147778368"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Split(ActiveDocument.BuiltInDocumentProperties(\"title\"), \"|||\")" ascii //weight: 1
        $x_1_2 = {4f 70 65 6e 20 [0-15] 28 31 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31}  //weight: 1, accuracy: Low
        $x_1_3 = {43 61 6c 6c 20 47 65 74 4f 62 6a 65 63 74 28 [0-15] 28 32 29 29 2e 4e 61 76 69 67 61 74 65 28 [0-15] 28 31 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {50 72 69 6e 74 20 23 31 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 0d 0a 43 6c 6f 73 65 20 23 31}  //weight: 1, accuracy: High
        $x_1_5 = {43 61 6c 6c 20 [0-25] 0d 0a 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_6 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 6d 61 69 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVK_2147778368_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVK!MTB"
        threat_id = "2147778368"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 65 78 65 63 20 70 28 [0-22] 29 20 26 20 22 20 22 20 26 20 70 28 [0-22] 29}  //weight: 1, accuracy: Low
        $x_1_2 = "Public Sub button1_Click()" ascii //weight: 1
        $x_1_3 = "= CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_4 = {69 6e 74 65 6c 20 3d 20 22 22 20 26 20 [0-22] 20 26 20 22 22 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = "= p(frm.button1.Caption)" ascii //weight: 1
        $x_1_6 = {66 72 6d 2e 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_7 = "<html><body><div id='content'>fTtl" ascii //weight: 1
        $x_1_8 = "ut = 600" ascii //weight: 1
        $x_1_9 = {3d 20 2e 54 61 67 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_10 = {3d 20 2e 43 61 70 74 69 6f 6e 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_AIH_2147778429_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.AIH!MTB"
        threat_id = "2147778429"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 65 78 65 63 20 52 65 70 6c 61 63 65 28 [0-37] 2c 20 22 31 22 2c 20 22 22 29 20 26 20 22 20 22 20 26 20 52 65 70 6c 61 63 65 28 [0-37] 20 22 31 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "= tr(\"<div id='content'>fTtl" ascii //weight: 1
        $x_1_3 = "= Replace(frm.cbtn1.Caption, \"1\", \"\")" ascii //weight: 1
        $x_1_4 = "= frm.cbtn1.Caption" ascii //weight: 1
        $x_1_5 = "frm.cbtn1_Click" ascii //weight: 1
        $x_1_6 = "= CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_7 = ".split('" ascii //weight: 1
        $x_1_8 = "Timeout = 600" ascii //weight: 1
        $x_1_9 = "Sub autoopen()" ascii //weight: 1
        $x_1_10 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_AII_2147778465_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.AII!MTB"
        threat_id = "2147778465"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Public Sub CommandButton1_Click()" ascii //weight: 1
        $x_1_2 = ".exec frm.CommandButton1.Tag & \" c:\\users\\public\\main.hta\"" ascii //weight: 1
        $x_1_3 = "= CreateObject(\"w\" & script & \"shell\")" ascii //weight: 1
        $x_1_4 = "Call frm.CommandButton1_Click" ascii //weight: 1
        $x_1_5 = ".Append_3 \"<div id='content'>fTtl" ascii //weight: 1
        $x_1_6 = "split('').reverse().join" ascii //weight: 1
        $x_1_7 = "Timeout = 60000" ascii //weight: 1
        $x_1_8 = "Sub autoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_AIEP_2147778800_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.AIEP!MTB"
        threat_id = "2147778800"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".exec p(textboxView) & \" \" & p(pasteIterator)" ascii //weight: 1
        $x_1_2 = "Public Sub button1_Click()" ascii //weight: 1
        $x_1_3 = "= CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_4 = "= \"\" & queryMain & \"\"" ascii //weight: 1
        $x_1_5 = "= p(frm.button1.Caption)" ascii //weight: 1
        $x_1_6 = {66 72 6d 2e 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_7 = "<html><body><div id='content'>fTtl" ascii //weight: 1
        $x_1_8 = "Timeout = 600" ascii //weight: 1
        $x_1_9 = {3d 20 2e 54 61 67 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_10 = {3d 20 2e 43 61 70 74 69 6f 6e 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_DRZ_2147778807_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.DRZ!MTB"
        threat_id = "2147778807"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 65 78 65 63 20 70 28 [0-19] 29}  //weight: 1, accuracy: Low
        $x_1_2 = "Public Sub button1_Click()" ascii //weight: 1
        $x_1_3 = "= CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_4 = "= p(frm.button1.Caption)" ascii //weight: 1
        $x_1_5 = {66 72 6d 2e 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_6 = "<html><body><div id='content'>fTtl" ascii //weight: 1
        $x_1_7 = "Timeout = 600" ascii //weight: 1
        $x_1_8 = {3d 20 2e 54 61 67 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_9 = {3d 20 2e 43 61 70 74 69 6f 6e 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVL_2147778989_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVL!MTB"
        threat_id = "2147778989"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 36 38 37 34 37 34 37 30 33 61 32 66 32 66 33 36 33 36 32 65 33 31 33 35 33 30 32 65 33 36 33 36 32 65 33 31 33 36 33 37 32 66 37 33 37 35 32 65 22 29 20 26 20 [0-15] 28 22 36 34 36 63 36 63 22}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 65 6c 6c 28 [0-15] 28 22 37 32 37 35 36 65 36 34 36 63 36 63 33 33 33 32 32 30 34 33 33 61 35 63 35 37 36 39 36 65 36 34 36 66 37 37 37 33 35 63 35 34 36 31 37 33 36 62 37 33 35 63 37 33 37 35 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-15] 28 22 34 31 34 34 34 66 34 34 34 32 32 65 22 29 20 26 20 [0-15] 28 22 35 33 37 34 37 32 36 35 36 31 36 64 22 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 32 29 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVL_2147778989_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVL!MTB"
        threat_id = "2147778989"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "repoListClear = functionRequest & \"c:\\users\\public\\nameV.hta\"" ascii //weight: 2
        $x_2_2 = "globalCollectDate = variableSwap & \"c:\\users\\public\\scrTextbox.hta\"" ascii //weight: 2
        $x_1_3 = {53 68 65 6c 6c 20 [0-20] 28 22 65 78 70 6c 6f 72 65 72 20 22 29 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73}  //weight: 1, accuracy: Low
        $x_1_4 = {4f 70 65 6e 20 [0-20] 28 22 22 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31}  //weight: 1, accuracy: Low
        $x_1_5 = "Print #1, ActiveDocument.Range.Text" ascii //weight: 1
        $x_1_6 = "Sub autoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_IcedID_RVN_2147779256_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVN!MTB"
        threat_id = "2147779256"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 63 3a 5c 70 72 6f 67 72 61 22 2c 20 4f 70 74 69 6f 6e 61 6c 20 [0-25] 20 3d 20 22 74 61 22}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 65 6c 6c [0-40] 28 22 65 78 70 6c 6f 72 65 72 20 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "Split(ActiveDocument.Range.Text, \"x\")" ascii //weight: 1
        $x_1_4 = {26 20 22 6d 64 61 74 61 5c [0-32] 2e 68 22 20 26}  //weight: 1, accuracy: Low
        $x_1_5 = {50 72 69 6e 74 20 23 31 2c 20 [0-32] 0d 0a 43 6c 6f 73 65 20 23 31 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_6 = "out & Chr(arr(cnt) Xor 100)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVO_2147779767_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVO!MTB"
        threat_id = "2147779767"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-20] 2e 68 22 2c 20 4f 70 74 69 6f 6e 61 6c 20 [0-20] 20 3d 20 22 74 22 2c 20 4f 70 74 69 6f 6e 61 6c 20 [0-20] 20 3d 20 22 61 22}  //weight: 1, accuracy: Low
        $x_1_2 = "Shell collectionCurrency(\"c:\\windows\\system32\\cmd /c \")" ascii //weight: 1
        $x_1_3 = "curBoolButt = \"!\"" ascii //weight: 1
        $x_1_4 = {26 20 43 68 72 28 [0-20] 28 [0-20] 29 20 58 6f 72 20 31 31 30 29}  //weight: 1, accuracy: Low
        $x_1_5 = "optionSel(ActiveDocument.Content)" ascii //weight: 1
        $x_1_6 = {4f 70 65 6e 20 63 6f 6c 6c 65 63 74 69 6f 6e 43 75 72 72 65 6e 63 79 28 22 22 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 0d 0a 50 72 69 6e 74 20 23 31 2c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVQ_2147779833_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVQ!MTB"
        threat_id = "2147779833"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"wscript.shell\").RegWrite listConst, 1, \"REG_DWORD\"" ascii //weight: 1
        $x_1_2 = {6c 65 6e 67 74 68 20 3d 20 4c 65 6e 28 [0-20] 29 0d 0a 46 6f 72 20 69 20 3d 20 30 20 54 6f 20 6c 65 6e 67 74 68 20 2d 20 31}  //weight: 1, accuracy: Low
        $x_1_3 = {72 65 76 65 72 73 65 64 54 65 78 74 20 26 20 4d 69 64 28 [0-20] 2c 20 28 6c 65 6e 67 74 68 20 2d 20 69 29 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_4 = "= GetObject(\"\", \"word.application\")" ascii //weight: 1
        $x_1_5 = "= \"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\\" & Application.Version & \"\\Word\\Security\\AccessVBOM\"" ascii //weight: 1
        $x_1_6 = ".Quit SaveChanges:=wdDoNotSaveChanges" ascii //weight: 1
        $x_1_7 = {76 61 6c 75 65 45 78 28 63 6f 75 6e 74 54 69 74 6c 65 2c 20 38 20 2f 20 34 2c 20 31 35 30 30 30 30 30 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_8 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVS_2147780189_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVS!MTB"
        threat_id = "2147780189"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Pattern = \"j|z|q|O|I|v|K|T|H|D|X|F|Z|M|U|N|Q|G|V|Y\"" ascii //weight: 1
        $x_1_2 = {53 65 74 20 [0-15] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 55 79 67 46 73 75 29}  //weight: 1, accuracy: Low
        $x_1_3 = ".Replace(Yoy1Rc(0), \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_ERS_2147780549_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.ERS!MTB"
        threat_id = "2147780549"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = ".Documents.Add.VBProject.VBComponents(\"ThisDocument\").CodeModule" ascii //weight: 1
        $x_1_3 = {31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = "= StrReverse(\"\\eciffO\\tfosorciM\\erawtfoS\\RESU_TNERRUC_YEKH\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_R_2147780552_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.R!MTB"
        threat_id = "2147780552"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "= StrReverse(UserForm1.TextBox1)" ascii //weight: 5
        $x_5_2 = "CreateObject(\"wscript.shell\")" ascii //weight: 5
        $x_1_3 = "= StrReverse(\"\\eciffO\\tfosorciM\\erawtfoS\\RESU_TNERRUC_YEKH\")" ascii //weight: 1
        $x_1_4 = "= StrReverse(\"MOBVsseccA\\ytiruceS\\droW\\\")" ascii //weight: 1
        $x_1_5 = " = \"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\\"" ascii //weight: 1
        $x_1_6 = " = \"\\Word\\Security\\AccessVBOM\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_IcedID_ERT_2147780612_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.ERT!MTB"
        threat_id = "2147780612"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = ".Documents.Add.VBProject.VBComponents(\"ThisDocument\").CodeModule" ascii //weight: 1
        $x_1_3 = {31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = "StrReverse(\"rawtfoS\\RESU_TNER\") & \"e\\Microsoft\\Office\\\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_ERV_2147780662_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.ERV!MTB"
        threat_id = "2147780662"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Sub button1_Click()" ascii //weight: 1
        $x_1_2 = {2e 65 78 65 63 20 28 73 72 28 [0-37] 29 29 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = "<html><body><div id='content1'>fTtl" ascii //weight: 1
        $x_1_4 = {66 72 6d 2e 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = "= Split(sr(ActiveDocument.BuiltInDocumentProperties(\"title\")), \" \")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_ERW_2147780677_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.ERW!MTB"
        threat_id = "2147780677"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Sub button1_Click()" ascii //weight: 1
        $x_1_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 20 28 73 72 28 [0-37] 29 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = "<html><body><div id='content1'>fTtl" ascii //weight: 1
        $x_1_4 = {66 72 6d 2e 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = "= Split(sr(ActiveDocument.BuiltInDocumentProperties(\"title\")), \" \")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_ERY_2147780752_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.ERY!MTB"
        threat_id = "2147780752"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "frm.click \"ript.sh\"" ascii //weight: 1
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 22 20 26 20 [0-37] 20 26 20 22 65 6c 6c 22 29 2e 65 78 65 63 28 72 65 76 28 74 69 74 6c 65 29 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = "= Split(rev(title), \" \")" ascii //weight: 1
        $x_1_4 = "= ActiveDocument.BuiltInDocumentProperties(\"title\")" ascii //weight: 1
        $x_1_5 = "<html><body><div id='content1'>fTtl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_ERZ_2147780897_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.ERZ!MTB"
        threat_id = "2147780897"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "= Replace(\"1\", \"VB\", \"ity\\Access1OM\")" ascii //weight: 1
        $x_1_3 = ".Documents.Add.VBProject.VBComponents(\"ThisDocument\").CodeModule" ascii //weight: 1
        $x_1_4 = "CreateObject(\"wscript.shell\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_FAAC_2147781595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.FAAC!MTB"
        threat_id = "2147781595"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 65 74 4f 62 6a 65 63 74 28 64 65 6c 65 74 65 54 65 6d 70 54 69 74 6c 65 20 26 20 22 22 29 2e 4e 61 76 69 67 61 74 65 20 74 69 74 6c 65 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = "title = ActiveDocument.BuiltInDocumentProperties(\"title\")" ascii //weight: 1
        $x_1_3 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 73 75 62 6a 65 63 74 22 29 20 26 20 22 22 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = "Open title For Output As #1" ascii //weight: 1
        $x_1_5 = {50 72 69 6e 74 20 23 31 2c 20 [0-32] 2e 52 61 6e 67 65 2e 54 65 78 74 02 00 43 6c 6f 73 65 20 23 31}  //weight: 1, accuracy: Low
        $x_1_6 = "Attribute VB_Base = \"1Normal.ThisDocument\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_FAAD_2147781695_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.FAAD!MTB"
        threat_id = "2147781695"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Split(ActiveDocument.BuiltInDocumentProperties(\"title\"), \"|||\")" ascii //weight: 1
        $x_1_2 = {43 61 6c 6c 20 47 65 74 4f 62 6a 65 63 74 28 6c 69 62 53 65 6c 65 63 74 28 32 29 29 2e 4e 61 76 69 67 61 74 65 28 6c 69 62 53 65 6c 65 63 74 28 31 29 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 02 00 50 72 69 6e 74 20 23 31 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 02 00 43 6c 6f 73 65 20 23 31 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_CLTA_2147782071_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.CLTA!MTB"
        threat_id = "2147782071"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Open \"collectionBoxConst.hta\" & buttTemplateHeader For Output As #1" ascii //weight: 1
        $x_1_2 = "Open \"swapHTpl.hta\" & buttTemplateHeader For Output As #1" ascii //weight: 1
        $x_1_3 = {50 72 69 6e 74 20 23 31 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 02 00 43 6c 6f 73 65 20 23 31 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 02 00 69 6e 69 74 56 62 61 02 00 53 68 65 6c 6c 20 22 65 78 70 6c 6f 72 65 72 20 63 6f 6c 6c 65 63 74 69 6f 6e 42 6f 78 43 6f 6e 73 74 2e 68 74 61 22 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 02 00 69 6e 69 74 56 62 61 02 00 53 68 65 6c 6c 20 22 65 78 70 6c 6f 72 65 72 20 73 77 61 70 48 54 70 6c 2e 68 74 61 22 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PDU_2147782095_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PDU!MTB"
        threat_id = "2147782095"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 20 [0-15] 28 22 65 78 70 6c 6f 72 65 72 20 22 29 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e 20 [0-15] 28 [0-15] 29 02 00 6c 65 6e 67 74 68 45 78 57 69 6e 20 3d 20 [0-15] 20 26 20 22 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 65 78 4d 65 6d 6f 72 79 44 6f 75 62 6c 65 2e 68 74 61 22 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PDV_2147782096_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PDV!MTB"
        threat_id = "2147782096"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 20 [0-15] 28 22 65 78 70 6c 6f 72 65 72 20 22 29 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e 20 [0-15] 28 [0-15] 29 02 00 73 63 72 4c 65 6e 67 74 68 20 3d 20 [0-15] 20 26 20 22 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 62 75 74 74 43 61 70 74 2e 68 74 61 22 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_JAAA_2147782358_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.JAAA!MTB"
        threat_id = "2147782358"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub autoopen()" ascii //weight: 1
        $x_1_2 = "libLeftIndex" ascii //weight: 1
        $x_1_3 = "linkCollection = ActiveDocument.Content" ascii //weight: 1
        $x_1_4 = "linkCollection = Mid(linkCollection, 2, Len(linkCollection))" ascii //weight: 1
        $x_1_5 = "With tableTitle.Documents.Add.VBProject.VBComponents(\"ThisDocument\").CodeModule" ascii //weight: 1
        $x_1_6 = "= \"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\\" & Application.Version & \"\\Word\\Security\\AccessVBOM\"" ascii //weight: 1
        $x_1_7 = {57 69 74 68 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 02 00 2e 52 65 67 57 72 69 74 65 20 72 65 6d 6f 76 65 4e 65 78 74 2c 20 31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_JAAB_2147782360_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.JAAB!MTB"
        threat_id = "2147782360"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= ActiveDocument.Content" ascii //weight: 1
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 6f 72 64 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 02 00 57 69 74 68 20 [0-32] 2e 44 6f 63 75 6d 65 6e 74 73 2e 41 64 64 2e 56 42 50 72 6f 6a 65 63 74 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 28 22 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 29 2e 43 6f 64 65 4d 6f 64 75 6c 65}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 22 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 56 65 72 73 69 6f 6e 20 26 20 22 5c 57 6f 72 64 5c 53 65 63 75 72 69 74 79 5c 41 63 63 65 73 73 56 42 4f 4d 22 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {57 69 74 68 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 02 00 2e 52 65 67 57 72 69 74 65 20 [0-32] 2c 20 31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 51 75 69 74 20 53 61 76 65 43 68 61 6e 67 65 73 3a 3d 77 64 44 6f 4e 6f 74 53 61 76 65 43 68 61 6e 67 65 73 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_JAAC_2147782481_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.JAAC!MTB"
        threat_id = "2147782481"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Function bytesIndex(longRight, Optional winI = \"c:\\program\", Optional localCntW = \"a\")" ascii //weight: 1
        $x_1_2 = {57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 62 79 74 65 73 49 6e 64 65 78 28 22 63 3a 5c 5c 77 69 6e 64 6f 77 73 5c 5c 65 78 70 6c 6f 72 65 72 20 22 29 2c 20 2c 20 54 72 75 65 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 77 69 6e 49 20 26 20 22 64 61 74 61 5c [0-32] 2e 68 74 22 20 26 20 6c 6f 63 61 6c 43 6e 74 57 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {50 72 69 6e 74 20 23 31 2c 20 [0-32] 43 6c 6f 73 65 20 23 31 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_PVDD_2147782490_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.PVDD!MTB"
        threat_id = "2147782490"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 75 6e 63 74 69 6f 6e 20 [0-15] 28 [0-15] 2c 20 4f 70 74 69 6f 6e 61 6c 20 [0-25] 20 3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 22 2c 20 4f 70 74 69 6f 6e 61 6c 20 [0-15] 20 3d 20 22 61 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {26 20 22 64 61 74 61 5c [0-32] 2e 68 74 22 20 26}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = "Set WshShell = CreateObject(\"Wscript.Shell\")" ascii //weight: 1
        $x_1_5 = {57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 [0-15] 28 22 63 3a 5c 5c 77 69 6e 64 6f 77 73 5c 5c 65 78 70 6c 6f 72 65 72 20 22 29 2c 20 2c 20 54 72 75 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_JAAE_2147782703_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.JAAE!MTB"
        threat_id = "2147782703"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 22 2c 20 4f 70 74 69 6f 6e 61 6c 20 [0-32] 20 3d 20 22 61 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {26 20 22 64 61 74 61 5c [0-32] 2e 68 74 22}  //weight: 1, accuracy: Low
        $x_1_3 = {28 53 70 6c 69 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 2c 20 22 2d 22 29 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {28 22 63 3a 5c 5c 77 69 6e 64 6f 77 73 5c 5c 65 78 70 6c 6f 72 65 72 20 22 29 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {50 72 69 6e 74 20 23 31 2c 20 [0-32] 43 6c 6f 73 65 20 23 31 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_SSB_2147782850_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.SSB!MTB"
        threat_id = "2147782850"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Debug.Print CreateObject(lenVbWindow(\"llehs.tpircsw\")).RegWrite(arrPointer, 1, \"REG_DWORD\")" ascii //weight: 1
        $x_1_2 = "localCaptionMemory = Mid(optionEx, counterTempStorage, 1000000)" ascii //weight: 1
        $x_1_3 = "= VBA.StrReverse(requestDocument)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_SSB_2147782850_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.SSB!MTB"
        threat_id = "2147782850"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 20 [0-15] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 56 42 53 63 72 69 70 74 2e 52 65 67 45 78 70 22 29}  //weight: 1, accuracy: Low
        $x_2_2 = "Pattern = \"q|D|T|P|Y|w|B|V|U|I|O|Z|M|F|X|N|G|Q|L|K|z" ascii //weight: 2
        $x_2_3 = "Pattern = \"K|v|q|X|P|Z|j|N|F|T|B|Y|L|z|U|H|w|V|D|O|G" ascii //weight: 2
        $x_2_4 = ".Replace(XKU5nOfKqD(0), \"\")" ascii //weight: 2
        $x_2_5 = ".Replace(tyeaHf(0), \"\")" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_IcedID_JAAH_2147782938_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.JAAH!MTB"
        threat_id = "2147782938"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 63 3a 5c 70 72 6f 67 72 61 22 2c 20 4f 70 74 69 6f 6e 61 6c 20 [0-32] 20 3d 20 22 74 61 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {26 20 22 6d 64 61 74 61 5c [0-32] 2e 68 22 20 26}  //weight: 1, accuracy: Low
        $x_1_3 = {44 69 6d 20 6f 75 74 20 41 73 20 53 74 72 69 6e 67 02 00 6f 75 74 20 3d 20 22 22}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 53 70 6c 69 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 2c 20 22 78 22 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {44 65 62 75 67 2e 50 72 69 6e 74 20 53 68 65 6c 6c 28 54 72 69 6d 28 22 22 20 2b 20 [0-32] 28 [0-32] 20 26 20 22 6f 72 65 72 20 22 29 29 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_VI_2147783255_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.VI!MTB"
        threat_id = "2147783255"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "out = \"\"" ascii //weight: 1
        $x_1_2 = {53 68 65 6c 6c 20 [0-255] 28 22 63 6d 64 20 2f 63 20 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {20 26 20 22 72 73 5c 5c 70 75 62 6c 69 63 5c 5c [0-32] 2e 68 22 20 26 20}  //weight: 1, accuracy: Low
        $x_1_4 = {53 70 6c 69 74 28 [0-255] 2c 20 22 23 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = "out & Chr(arr(cnt) Xor 121)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RVH_2147815496_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RVH!MTB"
        threat_id = "2147815496"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "GetObject(WCR_Aw(\"WA5cGy4d\")).Environment(WCR_Aw(\"tcazB8L_7J\")).Remove" ascii //weight: 5
        $x_5_2 = "GetObject(hoCHrGBZH(\"gwNLW1Bay4\")).Environment(hoCHrGBZH(\"ScmozQXgoo4ly\")).Remove" ascii //weight: 5
        $x_5_3 = "GetObject(pVLvRi(\"gzVReFWZewf3b\")).Environment(pVLvRi(\"cmO9Hbz9ck\")).Remove" ascii //weight: 5
        $x_1_4 = {73 68 65 6c 6c 43 6f 64 65 2c 20 [0-39] 2c 20 36 34 2c 20 56 61 72 50 74 72 28 [0-39] 29 0d 0a 47 65 74 4f 62 6a 65 63 74}  //weight: 1, accuracy: Low
        $x_1_5 = "StrReverse(ActiveDocument.CustomDocumentProperties(strInput))" ascii //weight: 1
        $x_1_6 = "Sub Document_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_IcedID_SIS_2147816496_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.SIS!MTB"
        threat_id = "2147816496"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= StrReverse(ActiveDocument.CustomDocumentProperties(strInput))" ascii //weight: 1
        $x_1_2 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 [0-31] 28 22 [0-31] 22 29 29 2e 56 61 6c 75 65 29}  //weight: 1, accuracy: Low
        $x_1_3 = "Sub Document_Open()" ascii //weight: 1
        $x_1_4 = {73 68 65 6c 6c 43 6f 64 65 2c 20 [0-30] 2c 20 36 34 2c 20 56 61 72 50 74 72 28 [0-30] 29 0d 0a 47 65 74 4f 62 6a 65 63 74}  //weight: 1, accuracy: Low
        $x_1_5 = "(0, shellCode, 1, shellCode)" ascii //weight: 1
        $x_1_6 = "Int(Rnd(23)) > 2 Then" ascii //weight: 1
        $x_1_7 = "= Timer() + (Finish)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_ZSM_2147829841_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.ZSM!MTB"
        threat_id = "2147829841"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ",0&,0&,0&,0&redim(1)endsubfunction()=" ascii //weight: 1
        $x_1_2 = "for=0to()-1step2=/2()=255-(&(,)&(,+1))next=endfunctionfunction" ascii //weight: 1
        $x_1_3 = "&mid(strinput,len(strinput)-k,1)nextendfunctionfunction(,)=mid(,+1,1)endfunctionfunction()=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RESM_2147830669_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RESM!MTB"
        threat_id = "2147830669"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rn&ld3lu&2" ascii //weight: 1
        $x_1_2 = {72 61 72 74 64 3a 5c 70 5c 63 61 61 6f 67 6d 22 29 26 [0-31] 28 31 32 29 26 [0-31] 28 22 64 6c 2e 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "c/hurlf:1uopc1ytrlnrcv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_RFSM_2147830670_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.RFSM!MTB"
        threat_id = "2147830670"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "auqjoixe.vjl" ascii //weight: 1
        $x_1_2 = "=array(\"31\",\"c0\",\"c2\",\"18\",\"00\")#endifvpe,32,64,0" ascii //weight: 1
        $x_1_3 = "=array(\"33\",\"c0\",\"c3\")#elseifwin32thenp=array(\"31\",\"c0\",\"c2\",\"18\",\"00\")#endifvpe,32,64,0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_IcedID_ASM_2147835054_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/IcedID.ASM!MTB"
        threat_id = "2147835054"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"146141190207210198196207144209196208200139140" ascii //weight: 1
        $x_1_2 = "= \"160138198216214215210208144" ascii //weight: 1
        $x_1_3 = "= \"219208207144198210209215200209215138192" ascii //weight: 1
        $x_1_4 = "= \"203215215211157146146" ascii //weight: 1
        $x_1_5 = "(CStr(137171))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

