rule Trojan_Win64_OnyxLocker_NLO_2147894992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OnyxLocker.NLO!MTB"
        threat_id = "2147894992"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OnyxLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 05 a3 d8 01 00 85 c9 bb ?? ?? ?? ?? 0f 44 c3 88 05 ?? ?? ?? ?? e8 9e 05 00 00 e8 d5 09 00 00 84 c0 75 04 32 c0 eb 14 e8 c8 45}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

