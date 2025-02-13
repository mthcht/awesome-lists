rule Ransom_Win32_DarkLoader_AA_2147844345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DarkLoader.AA!MTB"
        threat_id = "2147844345"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 08 88 04 0f 8b 45 ?? 88 14 08 0f b6 04 0f 8b 55 ?? 03 c6 0f b6 c0 0f b6 04 08 32 04 1a 88 03 43 83 6d ?? 01 8b 45 ?? 47 81 e7 ?? ?? ?? ?? 8a 14 0f 0f b6 f2 03 c6 25 ?? ?? ?? ?? 89 45 ?? 0f b6 04 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

