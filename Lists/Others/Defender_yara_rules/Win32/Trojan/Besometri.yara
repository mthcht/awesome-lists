rule Trojan_Win32_Besometri_2147706572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Besometri"
        threat_id = "2147706572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Besometri"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetBedtime" ascii //weight: 1
        $x_1_2 = "Veinstone" ascii //weight: 1
        $x_1_3 = {f7 e9 8b c1 c1 f8 1f c1 fa 04 2b d0 6b c2 65 2b c8 3b e9 7d 06}  //weight: 1, accuracy: High
        $x_1_4 = {b8 83 9a 37 2f f7 e9 8b c1 c1 f8 1f c1 fa 0d 2b d0 69 c2 7f ad 00 00 2b c8 75 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

