rule Trojan_Win32_Scelp_A_2147619278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scelp.A"
        threat_id = "2147619278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scelp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 76 63 68 6f 73 74 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 10, accuracy: High
        $x_10_2 = "Applications\\iexplore.exe\\shell\\open\\command" wide //weight: 10
        $x_2_3 = "InternetOpenUrlA" ascii //weight: 2
        $x_2_4 = "GET %s HTTP/1.0" ascii //weight: 2
        $x_1_5 = "ShutdownWithoutLogon" wide //weight: 1
        $x_1_6 = "Stop360 Error!" wide //weight: 1
        $x_1_7 = {5f 00 6b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

