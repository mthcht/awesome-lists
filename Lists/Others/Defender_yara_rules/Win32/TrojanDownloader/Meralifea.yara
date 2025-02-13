rule TrojanDownloader_Win32_Meralifea_A_2147728267_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Meralifea.A"
        threat_id = "2147728267"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Meralifea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 7c 4a 00 00 68 70 4a 00 00 c7 45 ?? 53 29 00 00 c7 45 ?? 6f 29 00 00 c7 45 ?? 61 29 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {83 f8 7a 89 44 24 14 74 05 83 f8 6f 75 28 56 6a 00 ff d7 50 ff d5}  //weight: 2, accuracy: High
        $x_1_3 = "INSTALL_CID" ascii //weight: 1
        $x_1_4 = "INSTALL_SID" ascii //weight: 1
        $x_1_5 = "INSTALL_SOURCE" ascii //weight: 1
        $x_1_6 = "&sid=%u" ascii //weight: 1
        $x_1_7 = "&sz=" ascii //weight: 1
        $x_1_8 = "os=%d&ar=%d" ascii //weight: 1
        $x_3_9 = "sltp://setup.gohub.online:1108" ascii //weight: 3
        $x_2_10 = "/setup.bin?id=128" ascii //weight: 2
        $x_2_11 = "\\??\\NPF-{0179AC45-C226-48e3-A205-DCA79C824051}" ascii //weight: 2
        $x_1_12 = "\\.\\X:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

