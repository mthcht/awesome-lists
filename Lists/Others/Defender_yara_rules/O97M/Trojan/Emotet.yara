rule Trojan_O97M_Emotet_ARA_2147748050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Emotet.ARA!eml"
        threat_id = "2147748050"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= b & u & c & e & t" ascii //weight: 1
        $x_1_2 = "= z & v & n & m & k" ascii //weight: 1
        $x_1_3 = "n & d & n &" ascii //weight: 1
        $x_1_4 = "h = \"p\"" ascii //weight: 1
        $x_1_5 = {3d 20 64 75 64 61 20 26 20 22 20 22 20 26 20 6a 75 68 20 26 20 22 20 28 22 20 26 20 66 72 61 6e 20 26 20 22 22 20 26 20 61 79 20 26 20 22 2b 22 20 26 20 6e 61 74 20 26 20 61 79 20 26 20 22 29 3b 22 20 26 20 [0-15] 20 26 20 73 61 66 20 26 20 61 79 20 26}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 52 75 6e 28 [0-15] 20 26 20 [0-15] 2c 20 30 2c 20 46 61 6c 73 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Emotet_CS_2147748455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Emotet.CS!eml"
        threat_id = "2147748455"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "*s3=77696e6d676d74733a57696e33325f50726f6365737353746172747570" ascii //weight: 1
        $x_1_2 = "Call At(VEC, sHexDecode(colVariabili(\"s3\")), sHexDecode(colVariabili(\"s4\")))" ascii //weight: 1
        $x_1_3 = "Set oProcess = CreateObject(ge)" ascii //weight: 1
        $x_1_4 = "= oProcess.ExecMethod_(sHexDecode(\"437265617465\")" ascii //weight: 1
        $x_1_5 = {3d 20 72 65 70 28 56 45 43 2c 20 22 [0-6] 22 2c 20 22 68 74 74 70 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Emotet_RDD_2147824916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Emotet.RDD!MTB"
        threat_id = "2147824916"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"JJCCBB\"" ascii //weight: 1
        $x_1_2 = "on\",\"urldownloadtofil" ascii //weight: 1
        $x_1_3 = ".ocx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

