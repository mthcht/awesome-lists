rule Trojan_Win32_Taidder_A_2147650560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Taidder.A"
        threat_id = "2147650560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Taidder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 73 6a 6d 8d 85 d8 fd ff ff 50}  //weight: 1, accuracy: High
        $x_1_2 = "q=%c&id=%s&%c=%s&%c=%s&c=%s&l=%s&t=%u&lip=%s&ts=%s" ascii //weight: 1
        $x_1_3 = "McAfee Framework Service" ascii //weight: 1
        $x_1_4 = {89 f0 40 c6 04 ?? ?? ?? ?? 00 ce 89 f0 83 c0 02 c6 04 ?? ?? ?? ?? 00 cc}  //weight: 1, accuracy: Low
        $x_1_5 = {b9 1a 00 00 00 31 d2 f7 f1 89 d7 83 c7 20 81 f7 a1 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

