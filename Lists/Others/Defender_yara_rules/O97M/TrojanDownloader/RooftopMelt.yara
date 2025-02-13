rule TrojanDownloader_O97M_RooftopMelt_A_2147844031_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/RooftopMelt.A!dha"
        threat_id = "2147844031"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "RooftopMelt"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 73 3a 2f 2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-32] 2f 73 65 6e 64 4d 65 73 73 61 67 65}  //weight: 1, accuracy: Low
        $x_1_2 = "https://api.my-ip.io/ip" ascii //weight: 1
        $x_1_3 = "C:\\Users\\\" & GetUserName & \"\\AppData\\Roaming\\Microsoft\\Templates\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

