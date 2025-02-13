rule Trojan_Win64_Fuery_SIB_2147807571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fuery.SIB!MTB"
        threat_id = "2147807571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fuery"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 2b c8 48 d3 c9 48 98 [0-5] 4a 8d 54 04 ?? 0f bf ca 41 8b c8 66 0f c8 b8 ?? ?? ?? ?? f9 d3 c0 41 02 c0 41 32 04 11 88 02 0f 84 ?? ?? ?? ?? 49 ff c0 f9 49 81 f8 ?? ?? ?? ?? 0f 82 ?? ?? ?? ?? 48 8d 4c 24 01 66 40 0f b6 c5 9f 86 e0 48 8b 05 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {43 0f b6 14 02 45 0f b6 08 49 ff c0 84 c0 0f 84 ?? ?? ?? ?? 8b cd b8 ?? ?? ?? ?? f8 f9 d3 c0 f8 80 f9 ?? 40 02 c5 f9 49 81 fe ?? ?? ?? ?? 32 d0 8a 84 24 ?? ?? ?? ?? 48 ff c5 f9 84 d2 0f 84 ?? ?? ?? ?? 41 3a d1 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

