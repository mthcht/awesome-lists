rule Trojan_Win32_Akkiki_A_2147611772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Akkiki.A"
        threat_id = "2147611772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Akkiki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 84 24 fc 02 00 00 0b 00 00 00 8b c1 8b f7 c1 e9 02 bf ec a9 40 00 f3 a5 8b c8 33 c0 83 e1 03 f3 a4}  //weight: 1, accuracy: High
        $x_1_2 = " /v /y /r /f lsollo" ascii //weight: 1
        $x_1_3 = {0f be 34 10 83 c6 1c 81 fe 96 00 00 00 0f 87 e2 00 00 00 33 c9 8a 8e ?? ?? ?? 00 ff 24 8d ?? ?? ?? 00 c6 04 10 53 e9 ca 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

