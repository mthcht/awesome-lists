rule TrojanDropper_O97M_ZooFlip_A_2147956894_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/ZooFlip.A!dha"
        threat_id = "2147956894"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ZooFlip"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "createimagelib\"kernel32\"alias\"createprocessw\"" ascii //weight: 1
        $x_1_2 = "closeimagelib\"kernel32\"alias\"closehandle\"" ascii //weight: 1
        $x_1_3 = "deleteimagelib\"kernel32\"alias\"createfilew\"" ascii //weight: 1
        $x_1_4 = "readimagelib\"kernel32\"alias\"readfile\"" ascii //weight: 1
        $x_1_5 = "writeimagelib\"kernel32\"alias\"writefile\"" ascii //weight: 1
        $x_1_6 = "getimagesizelib\"kernel32\"alias\"getfilesize\"" ascii //weight: 1
        $x_1_7 = "getimageresolutionlib\"kernel32\"alias\"getfileattributesw\"" ascii //weight: 1
        $x_1_8 = "clsid4e77131d3629431c9818c5679dc83e81inprocserver32" ascii //weight: 1
        $x_1_9 = "clsid2227a2803aea1069a2de08002b30309dinprocserver32" ascii //weight: 1
        $x_1_10 = "getrgbapayloadbytes0thenexitfunctionend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanDropper_O97M_ZooFlip_C_2147956895_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/ZooFlip.C!dha"
        threat_id = "2147956895"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ZooFlip"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dimtsiassiwithtsi.cb=lenb(tsi).df=suqorsuhq.wsw=shqendwith" ascii //weight: 1
        $x_1_2 = {64 69 6d 74 73 61 [0-21] 61 73 70 69 64 69 6d [0-32] 61 73 73 74 72 69 6e 67 64 69 6d [0-32] 61 73 6c 6f 6e 67 [0-48] 28 30 26 2c 73 74 72 70 74 72 28 [0-16] 29 2c 30 26 2c 30 26 2c 74 72 75 65 2c 30 26 2c 62 79 76 61 6c 30 26 2c 73 74 72 70 74 72 28}  //weight: 1, accuracy: Low
        $x_1_3 = {74 79 70 65 73 69 63 62 61 73 6c 6f 6e 67 [0-3] 6c 72 61 73 6c 6f 6e 67 [0-3] 6c 64 61 73 6c 6f 6e 67 [0-3] 6c 74 61 73 6c 6f 6e 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

