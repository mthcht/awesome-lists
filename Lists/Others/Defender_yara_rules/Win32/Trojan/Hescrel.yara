rule Trojan_Win32_Hescrel_A_2147688998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hescrel.A"
        threat_id = "2147688998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hescrel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 3d 72 09 0a 49}  //weight: 1, accuracy: High
        $x_1_2 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 73 00 63 00 72 00 [0-10] 73 00 63 00 72 00 2e 00 6c 00 6e 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_3 = {52 74 6c 49 c7 45 ?? 6e 69 74 41 c7 45 ?? 6e 73 69 53 c7 45 ?? 74 72 69 6e 66 c7 ?? e8 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

