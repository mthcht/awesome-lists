rule Ransom_Win32_Roger_MKV_2147913414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Roger.MKV!MTB"
        threat_id = "2147913414"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Roger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 3c 8b 7c 24 4c 8b 2d ?? ?? ?? ?? 32 c3 03 5c 24 5c 88 01 8b 44 24 34 01 44 24 28 47 89 5c 24 48 89 7c 24 4c 3b 7e 04 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Roger_STT_2147913638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Roger.STT!MTB"
        threat_id = "2147913638"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Roger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 d3 e0 8b f7 c1 ee 05 03 74 24 38 03 44 24 28 89 74 24 10 8b c8 e8 35 fe ff ff 33 c6 2b e8 81 3d ?? ?? ?? ?? d5 01 00 00 89 44 24 24 c7 05 ?? ?? ?? ?? 00 00 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Roger_YAA_2147913685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Roger.YAA!MTB"
        threat_id = "2147913685"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Roger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 7d 38 03 45 60 83 3d 28 53 4e 00 00 89 45 6c 75 06 ff 05 20 53 4e 00 32 c1 88 45 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

