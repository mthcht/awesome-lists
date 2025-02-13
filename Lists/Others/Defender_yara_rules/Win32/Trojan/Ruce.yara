rule Trojan_Win32_Ruce_A_2147628999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ruce.gen!A"
        threat_id = "2147628999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ruce"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "SYSTEM\\\\CurrentControlSet\\\\Services\\\\SharedAccess\\\\Parameters\\\\FirewallPolicy\\\\StandardProfile\\\\AuthorizedApplications\\\\List" ascii //weight: 50
        $x_50_2 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 50
        $x_5_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 3a 2a 3a 45 6e 61 62 6c 65 64 3a 4f 75 74 70 72 65 73 73 00}  //weight: 5, accuracy: High
        $x_5_4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 3a 2a 3a 45 6e 61 62 6c 65 64 3a 4d 69 63 72 6f 73 6f 66 74 20 4f 6e 6c 69 6e 65 20 55 70 64 61 74 65 00}  //weight: 5, accuracy: High
        $x_1_5 = {25 50 44 46 2d 31 00 00 65 78 65 00 4e 65 74 00 63 6d 64 2e 65 78 65 00 4b 69 6c 46 61 69 6c}  //weight: 1, accuracy: High
        $x_1_6 = {4d 53 49 45 20 37 2e 30 3b 29 00 77 62 00 00 65 78 65 00 4e 65 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {21 40 23 24 25 5e 00 00 65 78 65 00 4e 65 74 00 63 6d 64 2e 65 78 65 00 64 69 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_5_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ruce_B_2147629007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ruce.gen!B"
        threat_id = "2147629007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ruce"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 83 c4 04 85 ff 75 ?? 68 20 4e 00 00 ff d3 46 83 fe 09 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 00 6a 2a ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 80 00 00 68 04 01 00 00 ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 22 20 2d 6e 6f 68 6f 6d 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

