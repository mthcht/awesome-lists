rule Ransom_Win32_Trigona_SA_2147845298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Trigona.SA!MTB"
        threat_id = "2147845298"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Trigona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 0b 8b 1e 30 0c 03 40 83 f8 ?? 75 ?? 33 c0 8b d0 81 e2 ?? ?? ?? ?? 79 ?? 4a 83 ca ?? 42 8b 4d ?? 0f b6 14 11 8b 0e 30 14 01 40 83 f8 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Trigona_MKV_2147847525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Trigona.MKV!MTB"
        threat_id = "2147847525"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Trigona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 8b 38 ff 97 88 00 00 00 8b 45 f8 0f b6 00 32 45 e4 88 06 8d 53 60 8d 43 61 b9 0f 00 00 00 e8 74 d1 f2 ff 0f b6 06 88 43 6f ff 45 ?? 46 ff 4d f4 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Trigona_A_2147848066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Trigona.A"
        threat_id = "2147848066"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Trigona"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/!autorun" wide //weight: 1
        $x_1_2 = "/test_cid" wide //weight: 1
        $x_1_3 = "/test_vid" wide //weight: 1
        $x_1_4 = "/autorun_only" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Trigona_ATR_2147906567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Trigona.ATR!MTB"
        threat_id = "2147906567"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Trigona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 89 45 ec 8d 45 ec 50 8d 45 f0 50 8d 45 f4 50 6a 00 6a 00 6a 01 68 30 01 00 00 8b 45 f8 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

