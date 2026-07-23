rule Trojan_Win64_Hawkeye_AEH_2147974339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Hawkeye.AEH!MTB"
        threat_id = "2147974339"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {45 31 c0 45 31 c9 45 31 d2 48 89 c1 4c 89 44 24 38 48 8d 15 b1 34 00 00 41 b8 c2 0b 00 00 44 89 4c 24 30 45 31 c9 c7 44 24 28 03 00 00 00 4c 89 54 24 20 ff 15}  //weight: 2, accuracy: High
        $x_1_2 = "START_SCREEN" ascii //weight: 1
        $x_1_3 = "STOP_SCREEN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

