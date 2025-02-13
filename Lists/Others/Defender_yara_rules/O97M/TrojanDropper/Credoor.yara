rule TrojanDropper_O97M_Credoor_A_2147716886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Credoor.A"
        threat_id = "2147716886"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Credoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 73 66 69 6c 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 02 00 05 00 22 20 26 20 4d 69 6e 75 74 65 28 4e 6f 77 29 20 26 20 53 65 63 6f 6e 64 28 4e 6f 77 29 20 26 20 22 02 00 05 00 2e (68|6a 73) 22}  //weight: 1, accuracy: Low
        $x_1_2 = {44 66 69 6c 65 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-112] 2e 78 6c 73 22}  //weight: 1, accuracy: Low
        $x_1_3 = {44 66 69 6c 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-112] 2e 78 6c 73 22}  //weight: 1, accuracy: Low
        $x_1_4 = "Shell \"cscript /E:vbscript \"\"\" & Jsfile & \"\"\"\", vbHide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

