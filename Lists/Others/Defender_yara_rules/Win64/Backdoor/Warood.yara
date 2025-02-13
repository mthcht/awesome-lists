rule Backdoor_Win64_Warood_A_2147706601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Warood.A"
        threat_id = "2147706601"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Warood"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c 3f 74 3d 3c 47 75 1e 80 7c 3b 01 45 75 17 80 7c 3b 02 54 75 10}  //weight: 1, accuracy: High
        $x_1_2 = {3c 6c 74 04 3c 72 75 7d 44 8b 44 24 34 41 8d 40 ff 3d fd ff 00 00 77 6d}  //weight: 1, accuracy: High
        $x_1_3 = {48 b8 63 6f 6e 6e 65 63 74 00 48 89 44 24 20}  //weight: 1, accuracy: High
        $x_1_4 = "dir=in action=allow protocol=UDP localport=%u" ascii //weight: 1
        $x_1_5 = "/logo.gif?m=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

