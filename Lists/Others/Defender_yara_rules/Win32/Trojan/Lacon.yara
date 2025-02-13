rule Trojan_Win32_Lacon_A_2147643432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lacon.A"
        threat_id = "2147643432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lacon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 ff ff ff 7f 68 d4 08 40 00 68 44 09 40 00 c3 68 df 08 40 00 68 50 09 40 00 c3 c1 e8 07 bb f0 08 40 00 03 c3 68 09 09 40 00 50 c3 33 c0 e8 53 00 00 00 8b ec 83 ec 04 5c 83 c4 12 68 8b e5 c3 90 90 90 eb e7}  //weight: 1, accuracy: High
        $x_1_2 = {e8 0a 00 00 00 30 02 42 e2 f6 e9 8f fc ff ff 52 b8 c0 08 40 00 50 8b 00 8b d0 d1 e0 33 c2 83 c0 21 5a 89 02 c1 e8 18 5a c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

