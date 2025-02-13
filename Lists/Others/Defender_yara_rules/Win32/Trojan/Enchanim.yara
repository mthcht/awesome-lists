rule Trojan_Win32_Enchanim_A_2147647691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Enchanim.A"
        threat_id = "2147647691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Enchanim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 38 06 00 01 40 74 ?? 8b 40 0c 80 38 f8 74 ?? 80 38 e4 74 ?? 80 38 ec 0f 84 ?? ?? ?? ?? 80 38 ed 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {81 38 06 00 01 40 74 ?? 8b 50 0c 80 3a f8 74 ?? 80 3a e4 74 ?? 80 3a ec 0f 84 ?? ?? ?? ?? 80 3a ed 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Enchanim_A_2147651862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Enchanim.gen!A"
        threat_id = "2147651862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Enchanim"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d8 8b 56 e8 01 f3 29 eb ff d6 83 ee 1c 57 56 8b 5e 04 8b 4e 08 8b 56 0c 8b 7e 10 8b 6e 18 8b 76 14}  //weight: 1, accuracy: High
        $x_1_2 = {b2 7a 88 14 ?? c1 ea 08 ?? 78 09 83 ?? 03 75 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Enchanim_B_2147658637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Enchanim.gen!B"
        threat_id = "2147658637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Enchanim"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 45 0c 74 0d 83 c6 04 47 ff 4d fc 75 df 31 c0 eb 1d 8b 55 f8 8b 42 24 03 45 08 0f b7 3c 78 8b 72 1c 03 75 08 8b 04 be 85 c0 74 03 03 45 08 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Enchanim_D_2147671017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Enchanim.D"
        threat_id = "2147671017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Enchanim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 38 06 00 01 40 74 ?? 8b 40 0c 80 38 ec 74 ?? 80 38 e4 74 ?? 80 38 ed 74 ?? b8 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {81 38 06 00 01 40 74 ?? 8b 48 0c 80 39 ec 0f 84 ?? ?? ?? ?? 80 39 e4 74 ?? 80 39 ed 0f 84 ?? ?? ?? ?? 80 39 f8 74 ?? 31 c9}  //weight: 1, accuracy: Low
        $x_4_3 = {b2 7a 88 14 ?? c1 ea 08 ?? 78 09 83 ?? 03 75 d2}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

