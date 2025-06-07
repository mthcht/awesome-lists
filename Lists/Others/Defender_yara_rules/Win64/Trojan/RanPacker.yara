rule Trojan_Win64_RanPacker_CCJZ_2147943022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RanPacker.CCJZ!MTB"
        threat_id = "2147943022"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RanPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 f4 48 63 d0 48 89 d0 48 c1 e0 02 48 01 d0 48 c1 e0 03 48 89 c2 48 8b 45 d0 48 01 d0 48 89 c1 48 8d 45 c0 48 89 c2 e8 ?? ?? ?? ?? 85 c0 75 ?? 8b 45 f4 48 63 d0 48 89 d0 48 c1 e0 02 48 01 d0 48 c1 e0 03 48 89 c2 48 8b 45 d0 48 01 d0 8b 40 0c 89 c2 48 8b 45 e8 48 01 d0 48 89 45 f8 eb ?? 83 45 f4 01 48 8b 45 d8 0f b7 40 06 0f b7 c0 39 45 f4 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

