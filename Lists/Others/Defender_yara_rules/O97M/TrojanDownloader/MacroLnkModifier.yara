rule TrojanDownloader_O97M_MacroLnkModifier_A_2147729580_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/MacroLnkModifier.A"
        threat_id = "2147729580"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "MacroLnkModifier"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".createobject(" ascii //weight: 1
        $x_1_2 = ".createshortcut(" ascii //weight: 1
        $x_1_3 = ".specialfolders(activesheet.range" ascii //weight: 1
        $x_1_4 = {2e 69 63 6f 6e 6c 6f 63 61 74 69 6f 6e 90 02 05 3d}  //weight: 1, accuracy: High
        $x_1_5 = {2e 61 72 67 75 6d 65 6e 74 73 90 02 05 3d}  //weight: 1, accuracy: High
        $x_1_6 = {2e 74 61 72 67 65 74 70 61 74 68 90 02 05 3d}  //weight: 1, accuracy: High
        $x_1_7 = {63 72 65 61 74 65 73 68 6f 72 74 63 75 74 28 90 02 10 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

