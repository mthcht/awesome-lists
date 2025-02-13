rule Trojan_Win32_Baiso_B_2147606079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Baiso.B"
        threat_id = "2147606079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Baiso"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 69 6e 61 6d 70 69 2e 65 78 65 00 75 70 64 61 74 65 72 65 61 6c}  //weight: 1, accuracy: High
        $x_1_2 = {5c 64 6c 6c 68 6f 73 74 73 2e 64 6c 6c 00 00 00 6d 73 6e 6e 74}  //weight: 1, accuracy: High
        $x_1_3 = "SOFTWARE\\Microsoft\\WINDOWS\\CURRENTVERSION\\RUN" ascii //weight: 1
        $x_1_4 = {00 5c 7b 70 63 68 6f 6d 65 7d 5c 00 00 2e 73 65 74 75 70 00 00 62 61 69 73 6f 00 00 00 6d 63 71 00 5c 6c 69 62}  //weight: 1, accuracy: High
        $x_1_5 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Baiso_A_2147606080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Baiso.A"
        threat_id = "2147606080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Baiso"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&Agent=%s&version=%s&infoversion=%s" ascii //weight: 1
        $x_1_2 = "update\\updatefile.lst" ascii //weight: 1
        $x_1_3 = {5c 73 79 73 75 70 64 61 74 65 2e 69 6e 69 00 00 5c 73 79 73 6f 70 74 69 6f 6e 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_4 = {73 65 6c 66 55 70 64 61 74 65 00 00 72 74 00 00 75 70 2e 64 61 74}  //weight: 1, accuracy: High
        $x_1_5 = "waitdown.lst" ascii //weight: 1
        $x_1_6 = "InternetConnect" ascii //weight: 1
        $x_1_7 = "Service Runned Now!" ascii //weight: 1
        $x_1_8 = "not found system directory!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

