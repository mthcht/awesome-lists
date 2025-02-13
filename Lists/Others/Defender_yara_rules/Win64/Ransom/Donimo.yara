rule Ransom_Win64_Donimo_PA_2147845432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Donimo.PA!MTB"
        threat_id = "2147845432"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Donimo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 63 c1 4c 8d 1d ?? ?? ?? ?? 42 8a 04 18 32 04 11 88 02 41 8d 41 01 25 0f 00 00 80 7d ?? ff c8 83 c8 f0 ff c0 48 ff c2 44 8b c8 49 ff ca 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

