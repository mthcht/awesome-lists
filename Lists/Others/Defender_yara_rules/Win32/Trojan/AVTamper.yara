rule Trojan_Win32_AVTamper_E_2147931624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AVTamper.E"
        threat_id = "2147931624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AVTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 5a 57 81 c7 a4 0f 00 00 81 cf 73 3b 01 00 81 cf 19 08 00 00 81 f7 7e 8a 00 00 5f}  //weight: 1, accuracy: High
        $x_1_2 = {b9 6b 00 00 00 66 89 8d ?? ?? ?? ?? ba 65 00 00 00 66 89 95 ?? ?? ?? ?? b8 72 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

