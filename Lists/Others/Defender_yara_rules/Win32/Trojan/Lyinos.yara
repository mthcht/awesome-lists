rule Trojan_Win32_Lyinos_A_2147681523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lyinos.A"
        threat_id = "2147681523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lyinos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 54 6a 00 6a 01 6a 14 e4 ?? 59 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 30 8f 86 b0 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

