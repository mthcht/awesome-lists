rule Trojan_Win64_Lummastealer_ZTS_2147941171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lummastealer.ZTS!MTB"
        threat_id = "2147941171"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lummastealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 c1 0f b6 c1 0f b6 84 04 ?? ?? ?? ?? 48 63 4c 24 70 48 8b 54 24 28 30 04 0a 8b 44 24 70 8b 44 24 70 8b 44 24 70 8b 44 24 70 b8 1d 32 cf 80 3d a7 a0 44 e5 0f 8f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

