rule Trojan_Win64_Embargo_PA_2147970988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Embargo.PA!MTB"
        threat_id = "2147970988"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Embargo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe c1 44 0f b6 c1 46 0f b6 8c 05 ?? ?? ?? ?? 44 00 c8 44 0f b6 d0 46 0f b6 9c 15 ?? ?? ?? ?? 46 88 9c 05 ?? ?? ?? ?? 46 88 8c 15 ?? ?? ?? ?? 46 02 8c 05 ?? ?? ?? ?? 45 0f b6 c1 46 0f b6 84 05 ?? ?? ?? ?? 44 30 44 15 f0 4c 8d 42 ?? 4c 89 c2 49 81 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

