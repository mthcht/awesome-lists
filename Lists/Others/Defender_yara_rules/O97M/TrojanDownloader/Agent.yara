rule TrojanDownloader_O97M_Agent_GVP_2147745167_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Agent.GVP!MTB"
        threat_id = "2147745167"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a 20 53 69 6e 28 [0-53] 20 2d 20 43 44 62 6c 28 [0-53] 29 20 2a 20 [0-53] 20 2a 20 [0-53] 29 20 2f 20 [0-53] 20 2a 20 43 4c 6e 67 28 [0-53] 20 2d 20 43 44 61 74 65 28 [0-53] 29 29 20 2f 20 [0-53] 20 2b 20 [0-53] 20 2f 20 28 [0-53] 20 2f 20 [0-53] 20 2d 20 [0-53] 20 2f 20 49 6e 74 28 [0-53] 20 2d 20 52 6f 75 6e 64 28 [0-53] 29 20 2b 20 [0-53] 20 2f 20 [0-53] 29 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 20 53 74 72 52 65 76 65 72 73 65 28 [0-53] 29 20 2b 20}  //weight: 1, accuracy: Low
        $x_1_3 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

