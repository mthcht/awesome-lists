rule Trojan_Win32_Clokgiya_A_2147708543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clokgiya.A"
        threat_id = "2147708543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clokgiya"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 b1 61 8b d0 81 e2 01 00 00 80 79 05 4a 83 ca fe 42 75 06 30 88 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {34 e9 b2 00 61 00 3e 8b 8e e8 d5 00 61 00 ea fd 36 06 6e a0 66 26 c0 30 61 00 61 07 ea 40 6d 8b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

