rule Trojan_Win64_Shakti_MKV_2147846661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shakti.MKV!MTB"
        threat_id = "2147846661"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shakti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 c2 8b 05 ?? ?? ?? ?? 29 c2 8b 05 ?? ?? ?? ?? 29 c2 8b 05 ?? ?? ?? ?? 29 c2 89 d0 48 63 d0 48 8b 85 ?? ?? ?? ?? 48 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 48 63 d0 48 8b 85 ?? ?? ?? ?? 48 39 c2 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

