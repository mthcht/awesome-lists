rule Trojan_Win32_Kates_A_2147625398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kates.A"
        threat_id = "2147625398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kates"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ac 3c f0 74 fb 88 c1 24 fe 3c f2 74 f3 3c 64 74 ef 88 c8 24 e7 3c 26 74 e7 88 c8 3c 66 75 04 fe c2 eb dd 3c 67 75 04 fe c3 eb d5}  //weight: 1, accuracy: High
        $x_1_2 = {49 6e 74 65 72 6e 65 74 00 00 00 00 2f 2f 66 48 71 71 00 00 52 65 66 65 72 65 72 3a 00 00 00 00 0d 0a 53 53 3a 20 00 00 48 6f 73 74 3a 00 00 00 5c 73 71 6c 73 6f 64 62 63 2e 63 68 6d 00 00 00 73 65 61 72 63 68 00 00 72 65 73 75 6c 74 73 2e 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

