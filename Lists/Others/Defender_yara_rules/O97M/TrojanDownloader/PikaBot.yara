rule TrojanDownloader_O97M_PikaBot_SS_2147903471_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/PikaBot.SS!MTB"
        threat_id = "2147903471"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "PikaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 69 6c 65 3a 2f 2f 2f 5c 5c 38 35 2e 31 39 35 2e 31 31 35 2e 32 30 5c 73 68 61 72 65 5c 72 65 70 6f 72 74 73 [0-2] 30 32 2e 31 35 2e [0-2] 32 30 32 34 [0-2] 31 2e 6a 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

