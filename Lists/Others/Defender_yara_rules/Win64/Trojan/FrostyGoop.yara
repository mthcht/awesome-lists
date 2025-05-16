rule Trojan_Win64_FrostyGoop_AFR_2147941523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FrostyGoop.AFR!MTB"
        threat_id = "2147941523"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FrostyGoop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 6d 00 48 8d 05 a9 7a 07 00 48 89 44 24 50 48 c7 44 24 58 08 00 00 00 48 8d 0d 57 73 07 00 48 89 4c 24 60 48 c7 44 24 68 07 00 00 00 48 8d 0d f4 69 07 00 48 89 4c 24 70 48 c7 44 24 78 03 00 00 00 48 8d 0d 3f 72 07 00 48 89 8c 24 80 00 00 00 48 c7 84 24 88}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

