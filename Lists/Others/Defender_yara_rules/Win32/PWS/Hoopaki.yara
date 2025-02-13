rule PWS_Win32_Hoopaki_A_2147611442_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Hoopaki.A"
        threat_id = "2147611442"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Hoopaki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 f4 e9 8b 45 14 8b 5d fc 2b c3 83 e8 05 89 45 f5 8d 45 f4 6a 05 50 ff 75 fc e8}  //weight: 1, accuracy: High
        $x_1_2 = {83 c6 32 81 fe f4 01 00 00 7c be}  //weight: 1, accuracy: High
        $x_1_3 = {2f 6c 69 6e 2e 61 73 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

