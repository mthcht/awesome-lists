rule Trojan_Win32_Bangsmoop_A_2147655542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bangsmoop.A"
        threat_id = "2147655542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bangsmoop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 00 20 00 00 66 09 48 16}  //weight: 1, accuracy: High
        $x_1_2 = {b8 00 20 00 00 66 09 46 16}  //weight: 1, accuracy: High
        $x_1_3 = {83 c4 0c 80 ?? e9 75}  //weight: 1, accuracy: Low
        $x_1_4 = {d8 f5 01 00 25 ff 00 00 0f 94 c1 04 00 33 c9 81}  //weight: 1, accuracy: Low
        $x_1_5 = {83 f8 66 74 ?? 83 f8 6b}  //weight: 1, accuracy: Low
        $x_1_6 = {0f b7 47 14 [0-2] 8d 74 38 18 6a 28 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

