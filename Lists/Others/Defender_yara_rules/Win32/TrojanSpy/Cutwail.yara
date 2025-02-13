rule TrojanSpy_Win32_Cutwail_A_2147598319_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Cutwail.gen!A"
        threat_id = "2147598319"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 84 b7 00 00 00 53 55 8b 2d ?? ?? ?? 13 56 68 ?? ?? ?? 13 83 c7 08 57 ff 15 ?? ?? ?? 13 85 c0 89 44 24 10 74 7a 80 3f 3c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Cutwail_B_2147599385_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Cutwail.gen!B"
        threat_id = "2147599385"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "71"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "maxtrybadfrom" ascii //weight: 10
        $x_10_2 = "\\wcx_ftp.ini" ascii //weight: 10
        $x_10_3 = "anonymous" ascii //weight: 10
        $x_10_4 = "test25" ascii //weight: 10
        $x_10_5 = "SMTP Timeout!" ascii //weight: 10
        $x_10_6 = "{rcpt_to}" ascii //weight: 10
        $x_10_7 = "{mail_from}" ascii //weight: 10
        $x_1_8 = "208.66.194.242" ascii //weight: 1
        $x_1_9 = "66.246.252.215" ascii //weight: 1
        $x_1_10 = "208.66.195.71" ascii //weight: 1
        $x_1_11 = "74.53.42.34" ascii //weight: 1
        $x_1_12 = "74.53.42.61" ascii //weight: 1
        $x_1_13 = "B68BA487FDE5899A8A4BA40BF8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Cutwail_C_2147600455_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Cutwail.gen!C"
        threat_id = "2147600455"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 3d 19 00 74 14 33 c9 66 8b 0e 51 ff d7 66 3d 19 00}  //weight: 2, accuracy: High
        $x_2_2 = {68 00 24 40 9c 56 ff 15 ?? ?? ?? ?? 56}  //weight: 2, accuracy: Low
        $x_1_3 = {64 61 74 61 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {6d 61 69 6c 73 70 65 63 74 72 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 4d 54 50 44 52 56 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Cutwail_D_2147606946_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Cutwail.gen!D"
        threat_id = "2147606946"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c0 05 50 68 ?? ?? ?? ?? 8d 77 21 6a 08 56 ff 15 ?? ?? ?? ?? 83 c4 1c eb 01 46 80 3e 00 75 fa 6a 09 68}  //weight: 2, accuracy: Low
        $x_1_2 = {57 68 93 1f 00 00 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 45 fe 01 3c 0a 75 21 38 5d ff 74 1c 6a 08 41 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Cutwail_E_2147609323_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Cutwail.gen!E"
        threat_id = "2147609323"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 0f 8b 44 24 18 c6 46 06 68 89 46 07 c6 46 0b c3}  //weight: 1, accuracy: High
        $x_1_2 = {8a 0c 32 3a cb 74 09 84 c9 74 05 32 cb 88 0c 32 42 3b d0 7c eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

