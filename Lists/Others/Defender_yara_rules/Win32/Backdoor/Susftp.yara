rule Backdoor_Win32_Susftp_A_2147606867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Susftp.A"
        threat_id = "2147606867"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Susftp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellExecute ok! :-)" ascii //weight: 1
        $x_1_2 = {53 74 61 72 74 20 43 6d 64 20 53 68 65 6c 6c 20 4f 4b 20 61 74 20 70 6f 72 74 3a 00 53 65 6e 64 20 62 61 63 6b 20 63 6d 64 73 68 65 6c 6c}  //weight: 1, accuracy: High
        $x_1_3 = "*** END OF APPLICATION ***" ascii //weight: 1
        $x_1_4 = "httpdownload" ascii //weight: 1
        $x_1_5 = "catch Screen finished. The BMP file is saved to " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

