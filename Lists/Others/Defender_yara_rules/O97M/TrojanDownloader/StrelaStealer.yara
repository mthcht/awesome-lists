rule TrojanDownloader_O97M_StrelaStealer_SIO_2147918839_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/StrelaStealer.SIO!MTB"
        threat_id = "2147918839"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "https://gitlab.com/DemoTrojan/real/-/raw/main/check.bat" ascii //weight: 1
        $x_1_2 = {53 68 65 6c 6c 20 28 22 63 6d 64 20 2f 63 20 63 75 72 6c 20 2d 4c 20 2d 6f 20 25 41 50 50 44 41 54 41 25 5c 50 75 6e 2e 62 61 74 20 22 20 26 20 [0-47] 20 26 20 22 20 26 26 20 25 41 50 50 44 41 54 41 25 5c 50 75 6e 2e 62 61 74 22 29 2c 20 76 62 48 69 64 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

