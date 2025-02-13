rule TrojanSpy_Win32_Enturp_A_2147650946_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Enturp.A"
        threat_id = "2147650946"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Enturp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a c1 c0 e8 04 c0 e1 04 0a c1 88 02 8a 4c 16 01 42 84 c9 75 eb}  //weight: 2, accuracy: High
        $x_1_2 = {43 6f 6d 41 67 74 2e 64 6c 6c 00 55 6e 48 6f 6f 6b 00 69 6e 73 74 61 6c 6c 68 6f 6f 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

