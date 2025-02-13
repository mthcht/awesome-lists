rule Backdoor_Win32_Scrimp_B_2147627323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Scrimp.B"
        threat_id = "2147627323"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Scrimp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 6f 6e 6b 65 79 2e 64 61 74 00 6a 61 70 63 70 65 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 6f 6e 6b 65 79 2e 64 61 74 00 61 66 78 6d 73 69 6e 63 69 65 6e 00}  //weight: 1, accuracy: High
        $x_5_3 = {5c 6d 73 65 78 74 6c 6f 67 2e 64 6c 6c 00 00 00 6d 73 6c 6f 67 00 00 00 4d 69 63 6f 53 6f 66 74}  //weight: 5, accuracy: High
        $x_5_4 = {6d 6f 6e 6b 65 79 2e 64 6c 6c 00 26 31 32}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Scrimp_C_2147627328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Scrimp.C"
        threat_id = "2147627328"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Scrimp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6d 6f 6e 6b 65 79 2e 64 61 74 00 61 66 78 6d 73 69 6e 63 69 65 6e 00}  //weight: 5, accuracy: High
        $x_5_2 = {20 3e 20 00 4d 69 63 6f 53 6f 66 74 45}  //weight: 5, accuracy: High
        $x_1_3 = {77 73 63 73 63 6f 6e 2e 64 6c 6c 00 31 32}  //weight: 1, accuracy: High
        $x_1_4 = {6d 6f 6e 6b 65 79 2e 64 6c 6c 00 26 31 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Scrimp_A_2147627449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Scrimp.gen!A"
        threat_id = "2147627449"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Scrimp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6d 6f 6e 6b 65 79 2e 64 61 74 00 61 66 78 6d 73 69 6e 63 69 65 6e 00}  //weight: 10, accuracy: High
        $x_10_2 = {6d 6f 6e 6b 65 79 2e 64 61 74 00 61 66 78 6d 66 6c 78 63 75 00}  //weight: 10, accuracy: High
        $x_10_3 = {6d 6f 6e 6b 65 79 2e 64 61 74 00 6a 61 70 63 70 65 65 72 00}  //weight: 10, accuracy: High
        $x_50_4 = {5c 6d 73 65 78 74 6c 6f 67 2e 64 6c 6c 00 00 00 6d 73 6c 6f 67 00 00 00 4d 69 63 6f 53 6f 66 74}  //weight: 50, accuracy: High
        $x_50_5 = {20 3e 20 00 4d 69 63 6f 53 6f 66 74 45}  //weight: 50, accuracy: High
        $x_1_6 = {77 73 63 73 63 6f 6e 2e 64 6c 6c 00 31 32}  //weight: 1, accuracy: High
        $x_1_7 = {6d 6f 6e 6b 65 79 2e 64 6c 6c 00 26 31 32}  //weight: 1, accuracy: High
        $x_1_8 = {68 73 63 61 6e 63 6f 6e 2e 64 6c 6c 00 32}  //weight: 1, accuracy: High
        $x_1_9 = {77 6d 70 6c 63 73 2e 64 6c 6c 00 26 31 32}  //weight: 1, accuracy: High
        $x_1_10 = {6d 73 76 6d 72 65 67 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_10_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

