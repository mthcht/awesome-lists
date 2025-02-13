rule Backdoor_Win32_Sanjicom_2147603130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sanjicom"
        threat_id = "2147603130"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sanjicom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 5c 77 73 32 5f 33 32 2e 64 6c 6c 00 00 00 5c 5c 2e 5c 52 64 70 45 74 68 00 00 25 73 5c 25 73 5c 25 73}  //weight: 1, accuracy: High
        $x_1_2 = {67 6c 70 2e 75 69 6e 00 25 73 5c 25 73 00 00 00 6d 73 76 6d 6a 65 65 74 00 00 00 00 53 65 42 61 63 6b 75 70 50 72 69 76 69 6c 65 67 65 00 00 00 53 65 52 65 73 74 6f 72 65 50 72 69 76 69 6c 65 67 65 00 00 52 64 70 44 69 72 76 65 72}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\TEMP\\kb0800.tmp" ascii //weight: 1
        $x_1_4 = {52 44 50 44 72 76 00 00 53 65 63 75 72 69 74 79 00 00 00 00 53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 25 75 5c 53 65 72 76 69 63 65 73 5c 54 63 70 69 70 5c 53 65 63 75 72 69 74 79}  //weight: 1, accuracy: High
        $x_1_5 = {73 79 73 74 65 6d 33 32 5c 25 73 00 72 64 70 64 72 76 2e 73 79 73 00 00 24 6b 62 00 25 73 5c 25 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Sanjicom_2147603133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sanjicom!sys"
        threat_id = "2147603133"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sanjicom"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\SystemRoot\\System32\\msvmjeet\\" wide //weight: 1
        $x_1_2 = "\\SystemRoot\\System32\\nxbjeet\\" wide //weight: 1
        $x_2_3 = {25 73 2a 25 75 2a 25 49 36 34 64 2a 25 75 7c 00 30 00 00 00 6e 64 69 73 2e 73 79 73}  //weight: 2, accuracy: High
        $x_1_4 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\RDPDrv" wide //weight: 1
        $x_1_5 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NXBDrv" wide //weight: 1
        $x_1_6 = "\\SystemRoot\\System32\\rdpdrv.sys" wide //weight: 1
        $x_1_7 = "\\SystemRoot\\System32\\nxbdrv.sys" wide //weight: 1
        $x_4_8 = "\\Security\\{A1E77841-653A-4319-88FE-7D4C1A3F666A}" wide //weight: 4
        $x_1_9 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

