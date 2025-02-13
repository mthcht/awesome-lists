rule TrojanDropper_O97M_Zdowbot_A_2147716762_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Zdowbot.A"
        threat_id = "2147716762"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Zdowbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "If gemini Then lamarckian = Left$(lamarckian, Len(lamarckian) - gemini)" ascii //weight: 1
        $x_1_2 = {3d 20 4d 69 64 28 22 [0-16] 77 69 [0-16] 22 2c 20 31 31 2c 20 32 29 20 26 20 4c 43 61 73 65 28 22 4e 6d 47 6d 22 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 5c 5c 3a 73 74 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 4c 43 61 73 65 28 22 4f 4f 54 22 29 20 2b 20 52 69 67 68 74 28 22 [0-16] 63 69 6d 76 32 22 2c 20 36 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

