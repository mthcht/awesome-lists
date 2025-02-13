rule Worm_Win32_Comers_A_2147664982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Comers.A"
        threat_id = "2147664982"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Comers"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 c6 44 24 ?? 6c c6 44 24 ?? 6f c6 44 24 ?? 72 88 5c 24 ?? c6 44 24 ?? 72 c6 44 24 ?? 2e}  //weight: 1, accuracy: Low
        $x_1_2 = {39 44 24 18 75 3c 6a 24 e8}  //weight: 1, accuracy: High
        $x_1_3 = {8a 06 3c 43 7c 04 3c 5a 7e}  //weight: 1, accuracy: High
        $x_1_4 = {ff d3 8b f0 83 fe ff 74 21 80 bc 24 40 01 00 00 2e}  //weight: 1, accuracy: High
        $x_1_5 = {8b c1 99 f7 fb 8a 04 2a 8a 14 ?? 32 d0 88 14 31 41 3b}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 63 6f 6d 72 65 73 2e 64 6c 6c 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

