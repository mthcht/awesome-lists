rule PWS_Win32_Daceluw_A_2147684911_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Daceluw.A"
        threat_id = "2147684911"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Daceluw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 5d d6 88 5d da 88 5d de c7 45 cc 68 74 74 70 c7 45 d0 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 dc 25 73 2d 25 88 5d e1 66 c7 45 e2 58 25 88 5d e5 66 c7 45 e6 58 25 88 5d e9 66 c7 45 ea 58 25 88 5d ed 66 c7 45 ee 58 25 88 5d f1 66 c7 45 f2 58 25 88 5d f5 66 c7 45 f6 58 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

