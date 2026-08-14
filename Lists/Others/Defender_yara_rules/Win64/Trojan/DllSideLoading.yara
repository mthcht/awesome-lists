rule Trojan_Win64_DllSideLoading_PH_2147976080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllSideLoading.PH!MTB"
        threat_id = "2147976080"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllSideLoading"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 b9 01 00 00 00 48 89 94 24 c0 00 00 00 49 b8 2d 7f 95 4c 2d f4 51 58 48 b8 55 55 55 55 55 55 55 55 48 89 84 24 40 14 00 00}  //weight: 1, accuracy: High
        $x_4_2 = {48 8b c2 48 c1 e8 3e 48 33 d0 49 0f af d0 48 03 d1 48 89 94 cc c0 00 00 00 48 ff c1 48 81 f9 38 01 00 00 72 db}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DllSideLoading_PI_2147976124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllSideLoading.PI!MTB"
        threat_id = "2147976124"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllSideLoading"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 b8 93 9b 83 9e 87 89 9e cc 48 89 44 24 ?? 48 b8 9f 99 83 81 85 93 9b 83 48 89 44 24 ?? 31 c0 48 83 f8 0d 74 0a 80 74 04 ?? cc 48 ff c0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

