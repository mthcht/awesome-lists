rule Trojan_Win32_Posdrop_B_2147735893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Posdrop.B!dha"
        threat_id = "2147735893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Posdrop"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 ff c0 80 3c 03 00 75 f7 bf 04 01 00 00 48 85 c0 75 23 e8 fc ed ff ff 8b d7 48 8b cb 4c 8b c0 e8 6d 1d 00 00 4c 8d 05 a0 da ff ff 8b d7 48 8b cb e8 7a 1d 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b cb e8 8e ed ff ff 85 c0 74 4a 48 8d 4c 24 20 4c 8b c3 48 8b d7 e8 40 1d 00 00 4c 8d 05 83 da ff ff 48 8d 4c 24 20 48 8b d7 e8 4a 1d 00 00 48 8d 54 24 20 48 8b cb ff 15 c8 c9 1e 00 c6 05 91 2b 00 00 01 ff 15 5b c9 1e 00 48 8b c8 33 d2 ff 15 60 ca 1e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

