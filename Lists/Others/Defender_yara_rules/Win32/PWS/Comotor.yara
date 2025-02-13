rule PWS_Win32_Comotor_A_2147620701_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Comotor.A"
        threat_id = "2147620701"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Comotor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 6f 6e 74 73 5c [0-16] 2e 66 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "%s?act=&d10=%s&d80=%d" ascii //weight: 1
        $x_1_3 = {3f 67 61 6d 65 3d [0-4] 26 70 61 72 61 3d 25 73 26 25 76 65 73 3d}  //weight: 1, accuracy: Low
        $x_1_4 = {49 6e 74 65 72 6e 65 74 43 6c 6f 73 65 48 61 6e 64 6c 65 00 49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 00 00 00 00 49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 00 00 00 49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 00 00 00 00 77 69 6e 69 6e 65 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Comotor_B_2147621469_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Comotor.B"
        threat_id = "2147621469"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Comotor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "63"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 00 00 00 00 41 70 70 49 6e 69 74 5f 44 4c 4c 73}  //weight: 10, accuracy: High
        $x_10_2 = "fonts\\ctm%02x*.ttf" ascii //weight: 10
        $x_10_3 = {73 79 73 63 74 6d 2e 43 4f 4d 52 65 73 4d 6f 64 75 6c 65 49 6e 73 74 61 6e 63 65 00 53 65 74 4d 73 67 48 6f 6f 6b 00 69 6e 73}  //weight: 10, accuracy: High
        $x_10_4 = "SeDebugPrivilege" ascii //weight: 10
        $x_10_5 = "Process32First" ascii //weight: 10
        $x_10_6 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_1_7 = {63 74 6d 25 64 00}  //weight: 1, accuracy: High
        $x_1_8 = {70 61 74 63 68 75 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {7a 68 65 6e 67 00}  //weight: 1, accuracy: High
        $x_1_10 = {67 61 6d 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_11 = {65 6c 65 6d 65 6e 74 63 6c 69 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_12 = {6c 69 76 65 75 70 64 61 74 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

