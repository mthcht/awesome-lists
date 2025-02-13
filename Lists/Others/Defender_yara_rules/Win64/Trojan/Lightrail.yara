rule Trojan_Win64_Lightrail_EC_2147918703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lightrail.EC!MTB"
        threat_id = "2147918703"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lightrail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 03 ce 48 ff c6 42 88 44 f1 3e 48 63 c2 49 3b c0 7c e0 8b 5d 9b 41 03 d8 eb 4c 45 8b cb 48 85 d2 7e 42 4c 8b 6d ef 4d 8b c3 4d 8b d5 41 83 e5 3f 49 c1 fa 06 4e 8d 1c ed 00 00 00 00 4d 03 dd 41 8a 04 38 41 ff c1}  //weight: 5, accuracy: High
        $x_5_2 = {b9 00 00 01 00 48 89 44 24 30 41 b9 01 00 00 00 48 89 44 24 28 41 b8 00 10 00 00 48 89 44 24 20}  //weight: 5, accuracy: High
        $x_2_3 = "VGAuth.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

