rule Trojan_Win64_Lurifax_A_2147980594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lurifax.A"
        threat_id = "2147980594"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lurifax"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d 4c 24 ?? ba 01 00 00 00 41 ff d0 48 8d 7c 24 ?? b9 1d 00 00 00 b8 00 00 00 00 f3 aa}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 b9 e8 03 00 00 ff d5 48 89 f8}  //weight: 1, accuracy: High
        $x_1_3 = {41 ff d0 48 8d 7c 24 ?? b9 1d 00 00 00 b8 00 00 00 00 f3 aa}  //weight: 1, accuracy: Low
        $x_1_4 = {ba 11 00 00 00 ff d3 85 c0 78 ?? 48 83 c4 ?? 5b 5f c3 b9 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {48 31 f0 48 89 44 24 ?? 48 c7 44 24 ?? 00 00 00 00 c7 44 24 ?? 80 00 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {ff d3 85 c0 78 ?? 48 83 c4 ?? 5b 5f c3}  //weight: 1, accuracy: Low
        $x_1_7 = {0f b6 54 04 ?? 83 f2 3f 88 54 04 ?? 48 83 c0 01 48 83 f8 07 75 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

