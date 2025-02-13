rule Trojan_Win32_Seeav_A_2147678431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Seeav.A"
        threat_id = "2147678431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Seeav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 4f 01 47 3a cb 75 f8 8b c8 c1 e9 02 f3 a5 68 ff 07 00 00 8b c8 8d 94 24 1d 0c 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 30 8d 85 e0 f7 ff ff 48 8a 48 01 40 3a cb 75 f8 8b}  //weight: 1, accuracy: High
        $x_2_3 = {43 72 65 64 65 6e 74 69 61 6c 73 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_1_4 = {25 73 25 64 5f 72 65 73 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {2e 32 34 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 6e 73 74 61 6c 6c 20 53 75 63 63 65 73 73 21 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_7 = {4d 44 44 45 46 47 45 47 45 54 47 49 5a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Seeav_B_2147693619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Seeav.B"
        threat_id = "2147693619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Seeav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[g_MyCommand]" ascii //weight: 1
        $x_1_2 = "Global\\USB_New_Infected" ascii //weight: 1
        $x_1_3 = {53 59 53 41 46 30 39 31 31 00}  //weight: 1, accuracy: High
        $x_1_4 = "rusbmon.exe" ascii //weight: 1
        $x_1_5 = {4d 44 44 45 46 47 45 47 45 54 47 49 5a 00}  //weight: 1, accuracy: High
        $x_1_6 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 44 41 54 00}  //weight: 1, accuracy: High
        $x_1_7 = "Microsoft\\Windows\\Desktop.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

