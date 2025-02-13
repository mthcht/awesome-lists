rule Trojan_Win32_Micrass_A_2147692653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Micrass.A"
        threat_id = "2147692653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Micrass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 b4 01 00 f0 00 00 ec 41 81 f9 00 14 00 00 72 ef}  //weight: 1, accuracy: High
        $x_1_2 = {0f 8c 84 00 00 00 8b 45 08 c1 e8 03 89 45 ec 6b c0 f8 89 4d f4 29 55 f4 01 45 08 57}  //weight: 1, accuracy: High
        $x_1_3 = {8b c7 8d 48 02 66 8b 10 83 c0 02 66 3b d3 75 f5 2b c1 d1 f8 48 8b c8 3b cb 76 0f 66}  //weight: 1, accuracy: High
        $x_1_4 = {81 bd cc 3f ff ff 39 12 54 68 75 13}  //weight: 1, accuracy: High
        $x_1_5 = {75 55 81 bd cc 3f ff ff 98 36 42 87 75 13}  //weight: 1, accuracy: High
        $x_1_6 = "IP:%s Port:%d" wide //weight: 1
        $x_1_7 = {4c 00 53 00 4d 00 41 00 53 00 53 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = "%.4X.exe" wide //weight: 1
        $x_1_9 = {6c 00 6f 00 61 00 64 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

