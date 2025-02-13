rule Trojan_Win32_Liften_B_143056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Liften.B"
        threat_id = "143056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Liften"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 63 6f 6e 73 6f 6c 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {4e 44 49 53 52 44 00}  //weight: 1, accuracy: High
        $x_3_3 = {8b 00 ff d0 8b 03 50 8b 44 24 ?? 8b 84 b8 04 20 00 00 50 8b 44 24 ?? 50 a1 ?? ?? ?? ?? 8b 00 ff d0}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

