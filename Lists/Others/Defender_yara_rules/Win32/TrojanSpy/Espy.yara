rule TrojanSpy_Win32_Espy_A_2147603194_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Espy.A"
        threat_id = "2147603194"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Espy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "B*\\AF:\\learn\\visual basic\\edu\\hack\\key logger\\EgySpy v1.11\\server\\EgySpy.vbp" wide //weight: 10
        $x_5_2 = {53 70 6f 6f 6c 00 4f 70 65 72 61 74 69 6e 67 20 53 79 73 74 65 6d 20 46 69 6c 65 00 00 45 67 79 53 70 79}  //weight: 5, accuracy: High
        $x_5_3 = {45 67 79 53 70 79 00 00 46 52 4d 4c 4f 47 00 00 6d 64 6c 41 63 74 69 76 65 57 69 6e 64 6f 77 00 72 65 67 00 57 69 6e 73 6f 63 6b 42 61 73 00 00 73 6d 74 70 6d 6f 64 75 6c 65}  //weight: 5, accuracy: High
        $x_1_4 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 1
        $x_1_5 = "winload" ascii //weight: 1
        $x_1_6 = "SUBJECT:" wide //weight: 1
        $x_1_7 = ".qmail@" wide //weight: 1
        $x_1_8 = "If wVersion == 257 then everything is kewl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Espy_B_2147605645_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Espy.B"
        threat_id = "2147605645"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Espy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mohamed\\Desktop\\EgySpy v1.13\\server\\EgySpy.vbp" wide //weight: 1
        $x_1_2 = "If wVersion == 257 then everything is kewl" wide //weight: 1
        $x_1_3 = {53 70 6f 6f 6c 00 4f 70 65 72 61 74 69 6e 67 20 53 79 73 74 65 6d 20 46 69 6c 65 00 00 45 67 79 53 70 79}  //weight: 1, accuracy: High
        $x_1_4 = "MAIL FROM:<" wide //weight: 1
        $x_1_5 = "RCPT TO:<" wide //weight: 1
        $x_1_6 = ".qmail@" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

