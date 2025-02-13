rule Trojan_Win32_Kurei_A_2147679166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kurei.A"
        threat_id = "2147679166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kurei"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 05 00 00 00 04 00 08 02 00 00 00 31 f1 63 14 00 00 00 04 67 41 4d 41 00 00 b1 9e 61 4c 41 f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

