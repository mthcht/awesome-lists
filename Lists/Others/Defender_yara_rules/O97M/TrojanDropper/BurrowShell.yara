rule TrojanDropper_O97M_BurrowShell_SJ_2147975395_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/BurrowShell.SJ!MTB"
        threat_id = "2147975395"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "BurrowShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"https://ftp.desco-gov-bd.workers.dev/" ascii //weight: 1
        $x_1_2 = "= \"https://fancy-voice-b182.goldibrowhoami.workers.dev/audiodg.pdf" ascii //weight: 1
        $x_1_3 = "Download \"https://test.netof66867.workers.dev/" ascii //weight: 1
        $x_1_4 = {45 78 65 63 75 74 65 43 6d 64 41 73 79 6e 63 20 64 65 63 6f 54 6f 45 78 65 63 20 26 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 22 20 26 20 22 [0-15] 2e 78 6c 73 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

