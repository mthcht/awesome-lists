rule Trojan_Win32_Tamgitel_A_2147842608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tamgitel.A"
        threat_id = "2147842608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tamgitel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 66 b9 [0-5] 80 34 11 04 [0-5] e2}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 60 a5 34 04 04 04 81 c4 7c}  //weight: 1, accuracy: High
        $x_1_3 = {57 37 df 52 c2 41 ?? 45 c2 41 ?? 67 c2 41 ?? 68 c2 41 ?? 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

