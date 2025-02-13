rule PWS_Win32_Kuoog_A_2147631837_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Kuoog.A"
        threat_id = "2147631837"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Kuoog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d3 8d 4d b8 51 8b 55 c0 52 6a 05 a1 ?? ?? ?? 10 50 ff d6 c6 45 d8 e8}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 0c 89 8d 0c 89 8d 0c 89 8d 34 c8 56}  //weight: 2, accuracy: High
        $x_1_3 = "us=%s&ps=%s&lv=%d&qu=%s&se=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

