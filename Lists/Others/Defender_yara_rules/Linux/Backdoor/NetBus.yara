rule Backdoor_Linux_NetBus_A_2147829076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/NetBus.A!xp"
        threat_id = "2147829076"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "NetBus"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b bd fc fb ff ff 31 c0 fc b9 ff ff ff ff f2 ae 89 ca f7 d2 4a}  //weight: 1, accuracy: High
        $x_1_2 = {8a 13 84 d2 74 09 43 47 8a 13 80 fa 0a 75 f1}  //weight: 1, accuracy: High
        $x_1_3 = {8b bd dc fd ff ff 80 3f 2f 75 01 47 57}  //weight: 1, accuracy: High
        $x_1_4 = {31 c0 fc b9 7f 00 00 00 f3 ab 66 ab aa 89 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

