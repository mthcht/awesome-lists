rule Ransom_Win32_ChipRansom_YAA_2147853259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ChipRansom.YAA!MTB"
        threat_id = "2147853259"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ChipRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 52 ff 15 ?? ?? ?? ?? 32 5d e7 6a 18 88 5d d0 e8 ?? ?? ?? ?? 83 c4 04 89 45 ec 89 7d fc 3b c7 74}  //weight: 1, accuracy: Low
        $x_1_2 = {72 96 8b 15 ?? ?? ?? ?? 85 d2 75 ?? 8b 45 cc 8b 4d e0 3b c8 7e ?? 6b c9 45 03 4d e8 8b f0 0f af f0 03 ce 89 4d e8 8b 45 dc 40 3b 45 0c 89 45 dc 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

