rule Trojan_Win32_Qidmorks_A_2147685391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qidmorks.A"
        threat_id = "2147685391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qidmorks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7f 4e 8d 45 f8 03 85 e4 f5 ff ff 2d 10 04 00 00 c6 00 00 8d 45 f8 03 85 e4 f5 ff ff 2d 10 06 00 00 c6 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {7f 1b 8d 45 f8 03 85 f4 fe ff ff 2d 00 01 00 00 c6 00 00 8d 85 f4 fe ff ff ff 00 eb d9}  //weight: 1, accuracy: High
        $x_1_3 = {3f 00 64 57 6c 6b 50 51 3d 3d 00 26 00 64 6d 56 79 50 51 3d 3d 00 62 57 73 39 00 62 33 4d 39 00 63 6e 4d 39 00 59 7a 30 3d 00 63 6e 45 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

