rule TrojanDownloader_Win32_Hokeydaph_A_2147647289_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hokeydaph.A"
        threat_id = "2147647289"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hokeydaph"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {e9 14 01 00 00 b8 63 00 00 00 66 89 85 70 e7 ff ff b9 3a 00 00 00 66 89 8d 72 e7 ff ff ba 5c}  //weight: 4, accuracy: High
        $x_4_2 = {0f b7 85 6e ff ff ff 99 b9 07 00 00 00 f7 f9 83 c0 01 66 89 85 60 ff ff ff 0f bf 95 60 ff ff ff 83 fa 05 75 12}  //weight: 4, accuracy: High
        $x_2_3 = "Bid: %s" wide //weight: 2
        $x_2_4 = "Hid: %s" wide //weight: 2
        $x_1_5 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

