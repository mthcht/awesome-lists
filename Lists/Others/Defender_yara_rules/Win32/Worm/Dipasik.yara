rule Worm_Win32_Dipasik_A_2147678478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dipasik.A"
        threat_id = "2147678478"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dipasik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c 00 3e 0d 0a 00 48 45 4c 4f 20 3c 00 00 40 00 00 00 31 37 33 2e 31 39 34 2e 36 35 2e 32 37 00 00 00 31 37 33 2e 31 39 34 2e 36 37 2e 32 36 00 00 00 31 37 33 2e 31 39 34 2e 37 33 2e 32 37 00 00 00 31 37 33 2e 31 39 34 2e 36 38 2e 32 37 00 00 00 37 34 2e 31 32 35 2e 31 33 33 2e 32 36 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 60 8d 8c 24 d0 03 00 00 68 3d 0d 00 00 51 c7 44 24 18 01 00 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dipasik_B_2147709370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dipasik.B!dha"
        threat_id = "2147709370"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dipasik"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s\\c$\\winnt\\%s" ascii //weight: 1
        $x_1_2 = "%s\\c$\\windows\\%s" ascii //weight: 1
        $x_1_3 = {53 75 62 6a 65 63 74 3a 20 25 73 7c 25 73 7c 25 73 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = "<information@microsoft.com>" ascii //weight: 1
        $x_1_5 = "<microsoft@microsoft.com>" ascii //weight: 1
        $x_1_6 = {00 61 64 6d 69 6e 61 64 6d 69 6e 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 61 64 6d 69 6e 31 32 33 34 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 71 31 77 32 65 33 72 34 00}  //weight: 1, accuracy: High
        $x_2_9 = {c4 0c 3c 34 74 04 3c 35 75 0a c7 05 ?? ?? ?? ?? 01 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Dipasik_C_2147720994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dipasik.C!bit"
        threat_id = "2147720994"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dipasik"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {77 69 6e 65 5f 67 65 74 5f 75 6e 69 78 5f 66 69 6c 65 5f 6e 61 6d 65 00}  //weight: 2, accuracy: High
        $x_2_2 = "\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProle\\AuthorizedApplications\\List" ascii //weight: 2
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "q1w2e3r4" ascii //weight: 1
        $x_1_5 = "smtp://%s@%s|%s:%d|%s|%s" ascii //weight: 1
        $x_1_6 = "if exist \"%s\" goto repeat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

