rule Trojan_Win32_Jahomiv_A_2147722879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jahomiv.A"
        threat_id = "2147722879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jahomiv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8d 34 01 e8 ?? ff ff ff 30 06}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 04 02 03 07 03 c6 25 ff 00 00 00 8b f0 8a 07 88 45 ff}  //weight: 1, accuracy: High
        $x_1_3 = {c1 e8 10 88 06 46 8b c3 c1 e8 08 88 06 46 88 1e 46 33 db 88 5d 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

