rule Trojan_Win32_Lisiu_A_2147630964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lisiu.A"
        threat_id = "2147630964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lisiu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 09 80 34 31 02 41 3b c8 7c f7}  //weight: 2, accuracy: High
        $x_1_2 = {0f b6 ca d2 e0 0a d8 ff 45 fc 83 7d fc 08 88 1c 37 75 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

