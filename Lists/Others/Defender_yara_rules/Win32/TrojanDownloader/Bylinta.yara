rule TrojanDownloader_Win32_Bylinta_A_2147602777_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bylinta.A"
        threat_id = "2147602777"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bylinta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {b9 ff 01 00 00 33 c0 8d bd d1 f3 ff ff f3 ab 66 ab aa b9 00 02 00 00 33 c0 8d bd ?? ?? ff ff f3 ab 8d 95 ?? ?? ff ff bf}  //weight: 3, accuracy: Low
        $x_3_2 = {68 e5 65 32 01 8d 8d d0 f3 ff ff 51 e8 ?? ?? ff ff b9 19 00 00 00 33 c0 bf}  //weight: 3, accuracy: Low
        $x_2_3 = {74 13 6a 00 68 60 f0 00 00 68 12 01 00 00 50 ff 15 ?? ?? 00 10 6a 08 ff 15 ?? ?? 00 10 eb cd}  //weight: 2, accuracy: Low
        $x_6_4 = {43 43 44 4f 53 2e 64 6c 6c 00 49 6e 73 74 61 6c 6c 53 65 72 76 69 63 65 00 52 75 6e 64 6c 6c 49 6e 73 74 61 6c 6c 41 00 52 75 6e 64 6c 6c 55 6e 69 6e 73 74 61 6c 6c 41 00 53 65 72 76 69 63 65 4d 61 69 6e 00 55 6e 69 6e 73 74 61 6c 6c 53 65 72 76 69 63 65}  //weight: 6, accuracy: High
        $x_2_5 = "AVP.Product_Notification" ascii //weight: 2
        $x_2_6 = "CCatbylin" ascii //weight: 2
        $x_1_7 = "[%02X%02X%02X%02X%02X%02X]" ascii //weight: 1
        $x_1_8 = "AngelIE/1.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

