rule TrojanDownloader_O97M_Instabus_YA_2147733551_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Instabus.YA!MTB"
        threat_id = "2147733551"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Instabus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 73 69 65 78 65 63 [0-90] 2f 69 20 68 74 74 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

