rule Trojan_Win32_Teppto_A_2147630101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Teppto.A"
        threat_id = "2147630101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Teppto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {7e 00 31 00 2e 00 74 00 6d 00 70 00 00 00 00 00 7e 00 7e 00 00 00 00 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 70 00 6f 00 77 00 65 00 72 00 70 00 6e 00 74 00 2e 00 65 00 78 00 65 00 20 00 22 00 25 00 73 00 22 00 00 00 00 00 50 00 6f 00 77 00 65 00 72 00 50 00 6f 00 69 00 6e 00 74 00 2e 00 70 00 70 00 74 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = "CreateProcessW" ascii //weight: 1
        $x_1_3 = "GetTempPathW" ascii //weight: 1
        $x_1_4 = "TerminateProcess" ascii //weight: 1
        $x_1_5 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Teppto_A_2147630102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Teppto.A!dll"
        threat_id = "2147630102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Teppto"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 74 0b 48 74 04 b0 aa eb 06 b0 cc eb 02 b0 bb 66 0f b6 c0 c3}  //weight: 10, accuracy: High
        $x_10_2 = {2d aa 00 00 00 c7 05 ?? ?? ?? ?? 01 00 00 00 74 2d 83 e8 11 74 0a 83 e8 11 74 11 83 e8 11 75 29 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? eb 1c}  //weight: 10, accuracy: Low
        $x_1_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 25 73 00 00 00 2e 62 61 74 00 00 00 00 2e 65 78 65 00 00 00 00 25 73 25 73 00 00 00 00 2c 00 00 00 53 65 72 76 69 63 65 4d 61 69 6e 00 70 72 65 00 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_4 = {44 69 72 65 63 74 6f 72 79 41 00 00 6f 46 69 6c 65 41 00 00 4c 69 62 72 61 72 79 00 6f 77 6e 6c 6f 61 64 54 00 00 00 00 4d 79 4c 6f 61 64 00 00 55 52 4c 44}  //weight: 1, accuracy: High
        $x_1_5 = {41 75 74 6f 43 6f 6e 66 69 67 55 52 4c 00}  //weight: 1, accuracy: High
        $x_1_6 = "http://abc.abc.abc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

