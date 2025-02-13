rule Ransom_Win32_CubaPacker_SA_2147846481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CubaPacker.SA!MTB"
        threat_id = "2147846481"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CubaPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 b4 33 85 ?? ?? ?? ?? c1 c0 ?? 03 f0 89 5d ?? 89 75 ?? 89 75 ?? 33 f1 8b 4d ?? c1 c6 ?? 89 75 ?? 03 ce 89 75 ?? 8b 75 ?? 89 4d ?? 89 4d ?? 33 c8 c1 c1 ?? 83 6d ?? ?? 89 4d ?? 89 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

