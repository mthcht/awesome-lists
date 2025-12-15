rule Trojan_Win64_Shuyal_SPDP_2147959464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shuyal.SPDP!MTB"
        threat_id = "2147959464"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shuyal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 44 24 20 30 44 0c 21 0f b6 44 24 20 30 44 0c 22 0f b6 44 24 20 30 44 0c 23 0f b6 44 24 20 30 44 0c 24 0f b6 44 24 20 30 44 0c 25 0f b6 44 24 20 30 44 0c 26 0f b6 44 24 20 30 44 0c 27 0f b6 44 24 20 30 44 0c 28 0f b6 44 24 20 30 44 0d 80 0f b6 44 24 20 30 44 0d 81 0f b6 44 24 20 30 44 0d 82 0f b6 44 24 20 30 44 0d 83 0f b6 44 24 20 30 44 0d 84 0f b6 44 24 20 30 44 0d 85 0f b6 44 24 20 30 44 0d 86 0f b6 44 24 20 30 44 0d 87 48 83 c1 10 48 83 f9 50 0f 82}  //weight: 5, accuracy: High
        $x_4_2 = {0f b6 45 b7 30 44 0d b8 0f b6 45 b7 30 44 0d b9 48 83 c1 02 48 83 f9 3a 72}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

