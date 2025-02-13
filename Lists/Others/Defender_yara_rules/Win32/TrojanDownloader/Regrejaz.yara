rule TrojanDownloader_Win32_Regrejaz_A_2147647681_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Regrejaz.A"
        threat_id = "2147647681"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Regrejaz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "SystemCache.bat" ascii //weight: 4
        $x_4_2 = "system.conf" ascii //weight: 4
        $x_2_3 = "#kewl" ascii //weight: 2
        $x_2_4 = "gateway.php" ascii //weight: 2
        $x_2_5 = "manresa-pluja.com/bin" ascii //weight: 2
        $x_2_6 = "areyouaredo.com/" ascii //weight: 2
        $x_2_7 = "regdrv.exe" ascii //weight: 2
        $x_2_8 = {8d 45 e0 0f b7 55 f0 c1 e2 04 0f bf 4d f2 c1 e9 02 0a d1 e8}  //weight: 2, accuracy: High
        $x_1_9 = "google.com/" ascii //weight: 1
        $x_1_10 = "yahoo.com/" ascii //weight: 1
        $x_1_11 = "ask.com/" ascii //weight: 1
        $x_1_12 = "alexa.com/" ascii //weight: 1
        $x_1_13 = "live.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

