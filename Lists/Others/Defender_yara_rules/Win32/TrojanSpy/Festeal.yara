rule TrojanSpy_Win32_Festeal_A_2147598183_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Festeal.gen!A"
        threat_id = "2147598183"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Festeal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "69.46.16.191" ascii //weight: 1
        $x_1_2 = "088FA840-B10D-11D3-BC36-006067709674" ascii //weight: 1
        $x_1_3 = "sendmail" ascii //weight: 1
        $x_1_4 = "RCPT TO:" ascii //weight: 1
        $x_1_5 = "KeUnstackDetachProcess" ascii //weight: 1
        $x_1_6 = "KeStackAttachProcess" ascii //weight: 1
        $x_1_7 = "SYSTEM\\CurrentControlSet\\Services" ascii //weight: 1
        $x_1_8 = "GetWindowsDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Festeal_A_2147598184_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Festeal.A"
        threat_id = "2147598184"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Festeal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 bf cf ff db ff 08 8b ea 6a ff 6a 02 e8 0d 02 54 8b f0 83 fe ff 74 f0 57 56 48 b3 fd b3 ff eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Festeal_B_2147598185_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Festeal.B"
        threat_id = "2147598185"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Festeal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ec 83 ec 3c a1 00 e0 40 00 33 c5 89 45 fc 56 57 6a 06 59 be 68 20 0e 8d 7d e0 7f c6 be fb f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Festeal_B_2147598186_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Festeal.gen!B"
        threat_id = "2147598186"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Festeal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 32 ff 35 ?? ?? ?? ?? e8 ?? ?? 00 00 3b c3 74 0c 8b 40 0c 8b 00 8b 00 a3 ?? ?? ?? ?? 33 c0 68 ?? ?? ?? ?? 40 e8 ?? ?? 00 00 85 c0 59 74 ?? a1 ?? ?? ?? ?? 39}  //weight: 1, accuracy: Low
        $x_1_2 = {66 83 fd 19 74 0c 66 83 fd 50 74 06 66 83 fd 6e 75 13 ff 74 24 10 ff 15 ?? ?? 40 00 85 db 74 3a 0f b7 c5 eb 29}  //weight: 1, accuracy: Low
        $x_1_3 = {66 83 fd 19 0f b7 f8 74 0c 66 83 fd 50 74 06 66 83 fd 6e 75 14 8b 4c 24 10 51 ff 15 ?? ?? ?? 00 85 f6 74 34 0f b7 c5 eb 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Festeal_C_2147602233_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Festeal.C"
        threat_id = "2147602233"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Festeal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {84 c9 74 0f 80 f9 40 74 26 8a 48 01 83 c0 01 0e 75 f1 80 38 fd fd 8f fd 17 33 c0 8b 8c 29 33 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Festeal_C_2147611907_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Festeal.gen!C"
        threat_id = "2147611907"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Festeal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "os=%d&ver=%s&idx=%s&user=%s" ascii //weight: 2
        $x_2_2 = "%s&ioctl=%d&data=%s" ascii //weight: 2
        $x_4_3 = {44 37 45 42 36 30 38 35 2d 45 37 30 41 2d 34 66 35 61 2d 39 39 32 31 2d 45 36 42 44 32 34 34 41 38 43 31 37 00}  //weight: 4, accuracy: High
        $x_8_4 = {c7 46 20 32 00 00 00 0f 84 ?? ?? 00 00 83 7e 14 24 0f 86 ?? ?? 00 00 6a 24 68 ?? ?? ?? ?? 50 e8}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

