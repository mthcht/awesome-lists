rule TrojanDropper_O97M_Ursnif_AE_2147744076_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Ursnif.AE!MTB"
        threat_id = "2147744076"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 5c [0-16] 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 [0-6] 28 22 [0-16] 22 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 68 72 28 22 26 68 22 20 26 20 4d 69 64 28 [0-16] 2c 20 [0-16] 2c 20 32 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= \"appdata\"" ascii //weight: 1
        $x_1_4 = "= \"\"" ascii //weight: 1
        $x_1_5 = "= Fix(" ascii //weight: 1
        $x_1_6 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-16] 28 29 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_7 = "= New WshShell" ascii //weight: 1
        $x_1_8 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-16] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

