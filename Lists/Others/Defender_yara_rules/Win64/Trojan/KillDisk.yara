rule Trojan_Win64_KillDisk_MX_2147952276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillDisk.MX!MTB"
        threat_id = "2147952276"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillDisk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 0f 6e c6 0f 57 c9 0f 5b c0 f3 0f 11 4c 24 2c 0f 2f c1 0f 86 a3}  //weight: 1, accuracy: High
        $x_1_2 = "feder\\source\\repos" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

