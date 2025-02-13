rule PWS_Win32_Soyara_A_2147687764_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Soyara.A"
        threat_id = "2147687764"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Soyara"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SorayaV" ascii //weight: 1
        $x_1_2 = "mode=5&compinfo=" ascii //weight: 1
        $x_1_3 = {76 77 65 62 00 [0-16] 76 73 74 65 61 6c 74 68 00}  //weight: 1, accuracy: Low
        $x_1_4 = "POSMainMutex" ascii //weight: 1
        $x_1_5 = {54 72 61 63 6b 20 [0-16] 26 74 72 61 63 6b 3d}  //weight: 1, accuracy: Low
        $x_1_6 = {0f b6 d9 03 5d fc 8a 08 d3 c3 40 8a 08 89 5d fc 84 c9 75 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

