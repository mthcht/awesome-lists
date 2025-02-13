rule Trojan_Win32_Gupboot_A_2147666819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gupboot.A"
        threat_id = "2147666819"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gupboot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {47 62 70 54 65 6d 70 00 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 6c 6c 20 55 73 65 72 73 5c}  //weight: 5, accuracy: High
        $x_5_2 = {4d 00 42 00 52 00 21 00 [0-16] 4d 00 42 00 52 00 21 00 [0-32] 4d 00 42 00 52 00 [0-32] 4d 00 42 00 52 00 21 00 [0-6] 41 00 3a 00 [0-6] 5c 00 5c 00 2e 00 5c 00 25 00 73 00}  //weight: 5, accuracy: Low
        $x_1_3 = {5c 00 47 00 62 00 70 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-6] 53 00 65 00 63 00 75 00 4c 00 6f 00 67 00 69 00 6e 00 45 00 78 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\golfinfo.ini" wide //weight: 1
        $x_1_5 = "OnUpdateStart from super server" wide //weight: 1
        $x_1_6 = "Read GBP Data failed" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Gupboot_B_2147678996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gupboot.B"
        threat_id = "2147678996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gupboot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Starting GBP..." ascii //weight: 2
        $x_2_2 = {67 00 6f 00 6c 00 66 00 69 00 6e 00 66 00 6f 00 2e 00 69 00 6e 00 69 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {6d 00 6b 00 75 00 70 00 64 00 61 00 74 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_4 = {49 00 44 00 52 00 5f 00 42 00 49 00 4e 00 41 00 52 00 59 00 00 00}  //weight: 2, accuracy: High
        $x_8_5 = {40 3d e0 01 00 00 72 ee 81 7c 24 08 4d 53 4d 50 75}  //weight: 8, accuracy: High
        $x_8_6 = {52 66 a5 6a 1e 89 4c 24 24 c7 44 24 28 5f 47 42 50}  //weight: 8, accuracy: High
        $x_8_7 = {bf 5f 47 42 50 39 7b 04 74 34}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_8_*) and 1 of ($x_2_*))) or
            ((3 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Gupboot_A_2147681702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gupboot.gen!A"
        threat_id = "2147681702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gupboot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5c 00 47 00 62 00 70 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-6] 53 00 65 00 63 00 75 00 4c 00 6f 00 67 00 69 00 6e 00 45 00 78 00 2e 00 65 00 78 00 65 00}  //weight: 5, accuracy: Low
        $x_5_2 = {4d 00 42 00 52 00 21 00 [0-16] 4d 00 42 00 52 00 21 00 [0-32] 4d 00 42 00 52 00 [0-32] 4d 00 42 00 52 00 21 00 [0-6] 41 00 3a 00 [0-6] 5c 00 5c 00 2e 00 5c 00 25 00 73 00}  //weight: 5, accuracy: Low
        $x_1_3 = {5c 00 2a 00 2e 00 2a 00 [0-10] 25 00 64 00 2e 00 25 00 64 00 2e 00 25 00 64 00 2e 00 25 00 64 00 [0-10] 5f 75 6e 69 6e 73 65 70 2e 62 61 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

