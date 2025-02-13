rule Trojan_Win32_Encoder_A_2147657413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Encoder.A"
        threat_id = "2147657413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Encoder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TileWallpaper" ascii //weight: 1
        $x_2_2 = "0586308904327131" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Encoder_B_2147671326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Encoder.B"
        threat_id = "2147671326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Encoder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TileWallpaper" ascii //weight: 1
        $x_2_2 = "81825095086403177709" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Encoder_B_2147671326_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Encoder.B"
        threat_id = "2147671326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Encoder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 17 00 00 7e 06 c6 45 fb 05 eb 12 03 00 81 7d}  //weight: 1, accuracy: Low
        $x_1_2 = {85 c0 79 05 05 ff 03 00 00 c1 f8 0a 88 45 fb}  //weight: 1, accuracy: High
        $x_1_3 = {8a 07 03 c0 88 07 ff 45 ?? 47 83 c3 04 ff 4d}  //weight: 1, accuracy: Low
        $x_1_4 = {7e 04 c6 45 fb 01 13 00 81 7d ?? 00 04 00 00 7d 0a 83 7d ?? 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

