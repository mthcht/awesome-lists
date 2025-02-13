rule Trojan_Win32_Postoli_A_2147684507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Postoli.A"
        threat_id = "2147684507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Postoli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 00 3f 00 75 00 70 00 64 00 61 00 74 00 65 00 3d 00 64 00 61 00 69 00 6c 00 79 00 26 00 72 00 61 00 6e 00 64 00 6f 00 6d 00 3d 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 53 76 63 68 6f 73 74 2d 57 69 6e 64 6f 77 73 2d 52 65 64 71 75 69 72 65 64 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\Microsoft\\Windows\\System\\Hidden" wide //weight: 1
        $x_1_4 = {53 79 73 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

