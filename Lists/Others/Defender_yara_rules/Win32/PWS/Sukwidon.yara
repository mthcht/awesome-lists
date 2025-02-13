rule PWS_Win32_Sukwidon_A_2147647279_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sukwidon.A"
        threat_id = "2147647279"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sukwidon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 68 6f 74 6f 28 25 73 2d 25 73 29 00}  //weight: 1, accuracy: High
        $x_1_2 = {77 69 6e 64 6f 75 73 2e 6b 7a 2f 69 6e 64 65 78 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 69 63 72 6f 73 6f 66 69 2e 6f 72 67 2f 69 6e 64 65 78 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_4 = "smtp_server=%s&smtp_port=%d&smtp_user=%s&smtp_pass=%s&" ascii //weight: 1
        $x_1_5 = "pop3_server=%s&pop3_port=%d&pop3_user=%s&pop3_pass=%s&" ascii //weight: 1
        $x_1_6 = {49 45 3a 50 73 77 50 72 6f 74 65 63 74 65 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

