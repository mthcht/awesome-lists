rule DDoS_Win32_Doscor_A_2147694890_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Doscor.A"
        threat_id = "2147694890"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Doscor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 45 f8 33 45 fc 69 c0 fd 43 03 00 05 c3 9e 26 00 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 8c a7 40 00}  //weight: 5, accuracy: High
        $x_1_2 = "AppleWebKit" ascii //weight: 1
        $x_1_3 = "https://psb4ukr.org/%d-%c/" ascii //weight: 1
        $x_1_4 = "https://coru.ws/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

