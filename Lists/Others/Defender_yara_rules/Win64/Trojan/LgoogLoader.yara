rule Trojan_Win64_LgoogLoader_NL_2147898686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LgoogLoader.NL!MTB"
        threat_id = "2147898686"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LgoogLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 b8 16 00 00 00 e8 89 06 00 00 85 c0 74 14 ff c3 48 63 cb 48 81 f9 ?? ?? ?? ?? 72 dc 48 8b 45 ?? eb 06 48 63 c3 48 03 c7}  //weight: 5, accuracy: Low
        $x_5_2 = {48 85 c0 0f 84 ec 36 00 00 48 8b c8 e8 2b 00 00 00 48 85 c0 0f 84 db 36 00 00 b9 ?? ?? ?? ?? 66 39 48 5c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

