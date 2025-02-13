rule Trojan_Win32_Notodar_A_2147689817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Notodar.A"
        threat_id = "2147689817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Notodar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 33 c0 3b f0 74 24 57 50 50 50 56 68 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {74 6f 48 56 89 45 fc 57 8b 45 fc 8b 4d 08 6a 05 6a 07 8d 34 43 58 e8}  //weight: 1, accuracy: High
        $x_1_3 = {8b f8 3b fd 75 2d 6a 00 53 8b c6 e8 ?? ?? ?? ?? 8b f8 3b fd 75 1a 8b 46 1c 66 89 68 12 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {72 00 75 00 6e 00 61 00 73 00 00 00 73 00 79 00 73 00 70 00 72 00 65 00 70 00 5c 00 73 00 79 00 73 00 70 00 72 00 65 00 70 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 00 00 25 00 73 00 5c 00 53 00 79 00 73 00 57 00 6f 00 77 00 36 00 34 00 5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00 00 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Notodar_A_2147690827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Notodar.A!!Notodar.gen!C"
        threat_id = "2147690827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Notodar"
        severity = "Critical"
        info = "Notodar: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "C: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 33 c0 3b f0 74 24 57 50 50 50 56 68 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {74 6f 48 56 89 45 fc 57 8b 45 fc 8b 4d 08 6a 05 6a 07 8d 34 43 58 e8}  //weight: 1, accuracy: High
        $x_1_3 = {8b f8 3b fd 75 2d 6a 00 53 8b c6 e8 ?? ?? ?? ?? 8b f8 3b fd 75 1a 8b 46 1c 66 89 68 12 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {72 00 75 00 6e 00 61 00 73 00 00 00 73 00 79 00 73 00 70 00 72 00 65 00 70 00 5c 00 73 00 79 00 73 00 70 00 72 00 65 00 70 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 00 00 25 00 73 00 5c 00 53 00 79 00 73 00 57 00 6f 00 77 00 36 00 34 00 5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00 00 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

