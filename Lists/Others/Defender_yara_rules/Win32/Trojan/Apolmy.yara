rule Trojan_Win32_Apolmy_B_2147688977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Apolmy.B"
        threat_id = "2147688977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Apolmy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 1d 03 00 00 00 c6 05 11 00 00 00 04 c7 05 5b 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {b8 fb ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

