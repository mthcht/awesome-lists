rule Trojan_Win32_Dedreftot_A_2147685109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dedreftot.A"
        threat_id = "2147685109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dedreftot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 0d c0 08 02 80 30 ?? 40 49 83 f9 00}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d5 8d 87 9f 01 00 00 80 20 7f 80 60 28 7f}  //weight: 1, accuracy: High
        $x_1_3 = {8b 14 24 8b 52 3c 8b c3 03 d0 81 c2 f8 00 00 00 0f b7 cf c1 e1 03 8d 0c 89 03 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

