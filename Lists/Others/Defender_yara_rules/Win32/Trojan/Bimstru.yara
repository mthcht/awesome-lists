rule Trojan_Win32_Bimstru_A_2147616537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bimstru.A"
        threat_id = "2147616537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bimstru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 41 04 83 c1 04 3b c3 7c 05 32 c2 88 06 46 4f 3b fb 89 7d 10 7f e9}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 68 80 04 00 00 8b 4d f4 51 8b 55 08 52 ff 15 ?? ?? 40 00 85 c0 75 02 eb 73}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 01 e9 8b 55 08 83 c2 01 89 55 08 8b 45 10 83 c0 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

