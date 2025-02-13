rule Worm_Win32_Sality_A_2147606698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sality.gen!A"
        threat_id = "2147606698"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 0f 85 31 01 00 00 0f be ?? d8 f6 ff ff 83 ?? 5a 0f 85 21 01 00 00 83 bd e8 f6 ff ff 02 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Sality_AT_2147632614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sality.AT"
        threat_id = "2147632614"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 94 05 b3 fa ff ff 83 fa 5c 74 12 68}  //weight: 1, accuracy: High
        $x_1_2 = {83 fa 50 7e 29 e8 ?? ?? ?? ?? 25 ff ff 00 00 99 b9 3c 00 00 00 f7 f9 8b 14 95 ?? ?? ?? ?? 52 8d 85 00 fc ff ff 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Sality_AU_2147636658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sality.AU"
        threat_id = "2147636658"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 00}  //weight: 10, accuracy: High
        $x_10_2 = {3a 2a 3a 45 6e 61 62 6c 65 64 3a 69 70 73 65 63 00}  //weight: 10, accuracy: High
        $x_1_3 = {68 74 74 70 3a 2f 2f 63 64 65 69 6e 61 61 2e 63 6f 6d 2f 73 6d 2e 70 68 70 3f 70 69 7a 64 61 31 3d 25 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 72 69 76 65 72 73 2e 6c 6e 6b 00 41 6e 6e 61 20 42 65 6e 73 6f 6e 20 53 65 78 20 76 69 64 65 6f 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 65 73 73 69 6f 6e 00 53 4f 46 54 57 41 52 45 5c 7a 72 66 6b 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

