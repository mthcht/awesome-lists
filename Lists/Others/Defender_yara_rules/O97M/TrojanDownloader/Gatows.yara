rule TrojanDownloader_O97M_Gatows_A_2147735772_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gatows.A"
        threat_id = "2147735772"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gatows"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 57 49 4e 44 4f 57 53 2e 4c 61 62 65 6c [0-2] 2e 54 61 67}  //weight: 1, accuracy: Low
        $x_1_2 = ".Run WINDOWS.Label1.Tag + \" \" & WINDOWS.Tag +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

