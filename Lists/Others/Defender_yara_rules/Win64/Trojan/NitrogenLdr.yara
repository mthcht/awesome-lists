rule Trojan_Win64_NitrogenLdr_GA_2147932554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NitrogenLdr.GA!MTB"
        threat_id = "2147932554"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NitrogenLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8b 8c 24 ?? ?? ?? ?? 0f b6 04 01 89 ?? 24 ?? 48 63 4c 24 ?? 33 d2 48 8b c1 48 f7 b4 24 ?? ?? ?? ?? 48 8b c2 48 8b 8c}  //weight: 3, accuracy: Low
        $x_1_2 = {48 8b 8c 24 [0-13] 33 c8 8b c1 48 63 4c 24 ?? 48 8b 94 24 ?? ?? ?? ?? 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

