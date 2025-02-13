rule Trojan_Win32_Arveye_A_2147606981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Arveye.A"
        threat_id = "2147606981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Arveye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 ff 01 0f 00 50 ff 15 08 60 40 00 85 c0 0f 95 c3 eb b4 cc 8b 44 24 04 69 c0 e8 03 00 00 50 ff 15 28 60 40 00}  //weight: 1, accuracy: High
        $x_1_2 = {e8 c9 ff ff ff 8d 44 24 0c 68 54 61 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

