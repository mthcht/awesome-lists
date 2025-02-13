rule Ransom_Win32_Cryptomix_A_2147723298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptomix.A"
        threat_id = "2147723298"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptomix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "All your files have been encrypted!" ascii //weight: 1
        $x_1_2 = "/C sc stop WinDefend" ascii //weight: 1
        $x_1_3 = "/C sc stop wscsvc" ascii //weight: 1
        $x_1_4 = "/C sc stop wuauserv" ascii //weight: 1
        $x_1_5 = "-----BEGIN PUBLIC KEY----- MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBg" ascii //weight: 1
        $x_3_6 = {53 6a 61 5b 6a 41 c7 45 ?? 1a 00 00 00 5a 0f b7 01 66 3b c3 72 ?? 83 f8 7a 77 ?? 83 e8 54 99 f7 7d ?? 03 d3 eb ?? 66 3b c2 72 ?? 83 f8 5a 77 ?? 83 e8 34 99 f7 7d ?? 83 c2 41 6a 41}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cryptomix_A_2147724243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptomix.A!!Cryptomix.gen!A"
        threat_id = "2147724243"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptomix"
        severity = "Critical"
        info = "Cryptomix: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "All your files have been encrypted!" ascii //weight: 1
        $x_1_2 = "/C sc stop WinDefend" ascii //weight: 1
        $x_1_3 = "/C sc stop wscsvc" ascii //weight: 1
        $x_1_4 = "/C sc stop wuauserv" ascii //weight: 1
        $x_1_5 = "-----BEGIN PUBLIC KEY----- MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBg" ascii //weight: 1
        $x_3_6 = {53 6a 61 5b 6a 41 c7 45 ?? 1a 00 00 00 5a 0f b7 01 66 3b c3 72 ?? 83 f8 7a 77 ?? 83 e8 54 99 f7 7d ?? 03 d3 eb ?? 66 3b c2 72 ?? 83 f8 5a 77 ?? 83 e8 34 99 f7 7d ?? 83 c2 41 6a 41}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

