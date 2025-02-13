rule PWS_Win32_Paymilon_A_2147627004_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Paymilon.A"
        threat_id = "2147627004"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Paymilon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 4f 50 33 20 50 61 73 73 77 6f 72 64 32 [0-6] 50 4f 50 33 20 53 65 72 76 65 72 [0-6] 50 4f 50 33 20 55 73 65 72 20 4e 61 6d 65 [0-6] 48 54 54 50 4d 61 69 6c 20 50 61 73 73 77 6f 72 64 32 [0-6] 48 6f 74 6d 61 69 6c [0-6] 48 54 54 50 4d 61 69 6c 20 55 73 65 72 20 4e 61 6d 65 [0-6] 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73}  //weight: 10, accuracy: Low
        $x_1_2 = {44 45 4c 20 6b 65 79 [0-6] 49 4e 53 45 52 54 20 6b 65 79 [0-6] 50 52 49 4e 54 20 53 43 52 45 45 4e 20 6b 65 79 [0-6] 45 58 45 43 55 54 45 20 6b 65 79}  //weight: 1, accuracy: Low
        $x_1_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 6e 74 65 6c 6c 69 46 6f 72 6d 73 5c 53 74 6f 72 61 67 65 32 [0-5] 68 74 74 70 3a 2f 2f [0-5] 43 6f 6f 6b 69 65 3a}  //weight: 1, accuracy: Low
        $x_1_4 = "%4d-%02d-%02d %02d:%02d:%02d" ascii //weight: 1
        $x_1_5 = "0x%02hx%02hx%02hx%02hx%02hx%02hx" ascii //weight: 1
        $x_1_6 = "\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "\\cred.txt" ascii //weight: 1
        $x_1_8 = {5c 63 72 65 64 31 00 00 5c 63 72 65 64 30 00 00 5c 6c 6f 67 30 30 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

