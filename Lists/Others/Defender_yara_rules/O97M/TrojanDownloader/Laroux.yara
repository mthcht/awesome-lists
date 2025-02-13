rule TrojanDownloader_O97M_Laroux_DA_2147915478_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Laroux.DA!MTB"
        threat_id = "2147915478"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Laroux"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"Scripting.FileSystemObject\").CreateTextFile(\"Z:\\syscalls\\0_\" & Int(Rnd * 10000 + 10000) & \".vba.csv\", True, True)" ascii //weight: 1
        $x_1_2 = "JbxB64Encode = Replace(jbxXmlNodeOb.Text, vbLf, \"\")" ascii //weight: 1
        $x_1_3 = {54 00 68 00 69 00 73 00 57 00 6f 00 72 00 6b 00 62 00 6f 00 6f 00 6b 00 2e 00 53 00 61 00 76 00 65 00 43 00 6f 00 70 00 79 00 41 00 73 00 20 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 3a 00 3d 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 50 00 61 00 74 00 68 00 20 00 26 00 20 00 22 00 5c 00 [0-15] 2e 00 78 00 6c 00 73 00 22 00}  //weight: 1, accuracy: Low
        $x_1_4 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 43 6f 70 79 41 73 20 46 69 6c 65 6e 61 6d 65 3a 3d 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 26 20 22 5c [0-15] 2e 78 6c 73 22}  //weight: 1, accuracy: Low
        $x_1_5 = {54 00 68 00 69 00 73 00 57 00 6f 00 72 00 6b 00 62 00 6f 00 6f 00 6b 00 2e 00 50 00 61 00 74 00 68 00 20 00 26 00 20 00 22 00 5c 00 22 00 20 00 26 00 20 00 4a 00 62 00 78 00 48 00 6f 00 6f 00 6b 00 5f 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00 5f 00 33 00 5f 00 28 00 ?? ?? 2c 00 20 00 54 00 68 00 69 00 73 00 57 00 6f 00 72 00 6b 00 62 00 6f 00 6f 00 6b 00 2e 00 4e 00 61 00 6d 00 65 00 2c 00 20 00 22 00 2e 00 78 00 6c 00 73 00 78 00 22 00 2c 00 20 00 22 00 2e 00 78 00 6c 00 73 00 22 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 22 20 26 20 4a 62 78 48 6f 6f 6b 5f 52 65 70 6c 61 63 65 5f 33 5f 28 ?? ?? 2c 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 4e 61 6d 65 2c 20 22 2e 78 6c 73 78 22 2c 20 22 2e 78 6c 73 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

