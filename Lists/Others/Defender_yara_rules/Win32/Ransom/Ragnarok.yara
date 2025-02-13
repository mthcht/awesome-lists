rule Ransom_Win32_Ragnarok_S_2147758414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ragnarok.S!MSR"
        threat_id = "2147758414"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ragnarok"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f1 8a 04 1a 88 04 3e 46 83 fe 40 e8 ?? ?? ff ff 33 d2 b9 3d 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ragnarok_PD_2147765241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ragnarok.PD!MTB"
        threat_id = "2147765241"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ragnarok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 fb 8b da 8b 95 f8 [0-4] 0f b6 84 1d ?? ?? ?? ?? 88 84 15 ?? ?? ?? ?? 88 8c 1d ?? ?? ?? ?? b9 06 00 00 00 0f b6 84 15 ?? ?? ?? ?? 33 d2 03 c6 f7 f1 0f b6 84 15 ?? ?? ?? ?? 30 87 ?? ?? ?? ?? 47 8b 85 f8 [0-4] 81 ff a6 10 00 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

