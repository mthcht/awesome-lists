rule Ransom_Win32_TeslaCryptPacker_2147809325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TeslaCryptPacker!MTB"
        threat_id = "2147809325"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCryptPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c9 74 09 8b 55 ?? ?? 55 ?? 89 55 ?? 8b 45 ?? ?? 45 ?? 89 45 ?? 8b 4d ?? ?? 4d ?? 89 4d ?? 8b 55 ?? ?? 55 ?? 89 55 ?? 8b 45 ?? ?? 45 ?? 89 45 ?? 8b 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {85 d2 74 09 8b 45 ?? ?? 45 ?? 89 45 ?? 8b 4d ?? ?? 4d ?? 85 c9 74 09 8b 55 ?? ?? 55 ?? 89 55 ?? 8b 45 ?? ?? 45 ?? 85 c0 74 09 8b 4d ?? ?? 4d ?? 89 4d ?? 8b 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

