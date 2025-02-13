rule Ransom_Win32_WastedLocker_WR_2147758334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WastedLocker.WR!MTB"
        threat_id = "2147758334"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WastedLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1f 4d 8a cb 47 e8 ?? ?? ff ff 0f b6 c8 0f b6 d3 83 e1 0f c1 ea 04 33 ca c1 e8 04 33 04 8e 85 ed 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c8 83 e1 0f c1 e8 04 33 04 8a c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WastedLocker_WT_2147758335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WastedLocker.WT!MTB"
        threat_id = "2147758335"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WastedLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 16 8b c2 23 c1 8b fa 0b f9 f7 d0 23 c7 8b c8 23 [0-4] 0b [0-4] f7 d1 23 c8 8b [0-4] 83 [0-4] 04 89 08 8a cb d3 ca 83 c6 04 4b 8b ca 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WastedLocker_SK_2147760787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WastedLocker.SK!MTB"
        threat_id = "2147760787"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WastedLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 08 5f 5b 5d c3 f0 00 eb ?? bb ?? ?? ?? ?? bb ?? ?? ?? ?? 31 0d ?? ?? ?? ?? bb ?? ?? ?? ?? a1 ?? ?? ?? ?? bb ?? ?? ?? ?? 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 53 8b 25 ?? ?? ?? ?? 58 8b e8 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 8b c0 8b c0 8b c0 8b c0 53 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_WastedLocker_MA_2147762177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WastedLocker.MA!MTB"
        threat_id = "2147762177"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WastedLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 d5 11 00 00 85 c0 74 48 c7 45 e4 ?? ?? ?? ?? 8b 4d f8 3b 0d ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 03 45 f8 8b 55 f4 0f be 04 02 89 45 e4 8b 4d f8 03 4d f0 8b 55 fc 8a 45 e4 88 04 0a 8b 4d f8 83 c1 01 89 4d f8 eb af}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

