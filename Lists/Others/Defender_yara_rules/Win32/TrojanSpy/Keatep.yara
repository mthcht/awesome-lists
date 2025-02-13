rule TrojanSpy_Win32_Keatep_A_2147605728_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keatep.A"
        threat_id = "2147605728"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keatep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 25 83 bd ?? ?? ff ff 15 74 1c 81 bd ?? ?? ff ff 49 08 00 00 74 10 81 bd ?? ?? ff ff 49 08 00 00 0f 85 ?? ?? 00 00 8b ?? ?? 0f be ?? 83 ?? 55 74 0b 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keatep_B_2147616019_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keatep.B"
        threat_id = "2147616019"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keatep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {6d 69 63 72 6f 75 70 64 61 74 65 31 34 2e 69 6e 66 6f 2f 69 66 72 61 6d 65 2e 74 78 74 00 00}  //weight: 8, accuracy: High
        $x_2_2 = {70 61 73 73 77 6f 72 64 00 00 00 00 53 4f 46 54 57 41 52 45 5c 46 61 72 5c 50 6c 75 67 69 6e 73 5c 46 54 50 5c 48 6f 73 74 73}  //weight: 2, accuracy: High
        $x_2_3 = {77 63 78 5f 66 74 70 2e 69 6e 69 00}  //weight: 2, accuracy: High
        $x_2_4 = "%s:*:Enabled:ipsec" ascii //weight: 2
        $x_2_5 = {68 74 74 70 00 00 00 00 61 6e 67 65 6c 00 00 00 00 47 6c 6f 62 61 6c 55 73 65 72 4f 66 66 6c 69 6e 65}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Keatep_C_2147618918_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keatep.C"
        threat_id = "2147618918"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keatep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://microupdate" ascii //weight: 1
        $x_1_2 = "SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii //weight: 1
        $x_1_4 = "%s:*:Enabled:ipsec" ascii //weight: 1
        $x_1_5 = {8d 85 e4 ea ?? ?? 50 68 3f 00 0f 00 6a 00 8b 0d ?? ?? ?? 00 51 68 01 00 00 80 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keatep_E_2147649743_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keatep.E"
        threat_id = "2147649743"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keatep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 17 8b 55 f8 81 e2 ff ff 00 00 d1 fa 81 f2 01 a0 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {6a 65 6f 52 33 57 71 31 00}  //weight: 2, accuracy: High
        $x_1_3 = {7c 24 70 61 73 73 3d 00 24 00 66 61 63 65 62 6f 6f 6b 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {26 72 65 64 69 72 65 63 74 5f 74 6f 3d 00 00 00 50 4f 53 54 [0-143] 77 70 2d 6c 6f 67 69 6e 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

