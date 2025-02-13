rule Ransom_Win64_BastaPacker_ZC_2147844141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BastaPacker.ZC!MTB"
        threat_id = "2147844141"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BastaPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 4c 8d 04 02 48 8b 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 48 98 48 01 d0 44 0f b6 08 8b 8d ?? ?? ?? ?? ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 6b c0 ?? 29 c1 89 c8 48 63 d0 48 8b 85 ?? ?? ?? ?? 48 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 48 63 d0 48 8b 85 ?? ?? ?? ?? 48 39 c2 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

