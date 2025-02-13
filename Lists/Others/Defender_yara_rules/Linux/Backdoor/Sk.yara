rule Backdoor_Linux_Sk_A_2147826659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Sk.A!xp"
        threat_id = "2147826659"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Sk"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 3c 8e 89 c1 d3 ef 89 f8 8b 55 f4 88 04 13 43 83 fb 07}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 10 cd 80 89 85 e8 df ff ff 85 c0 7d 02}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 0c 8b 18 89 df 89 c8 49 f2 ae f7 d1 49 8d 74 19 fc bf c0 c8 04 08}  //weight: 1, accuracy: High
        $x_1_4 = "it: Starting backdoor " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

