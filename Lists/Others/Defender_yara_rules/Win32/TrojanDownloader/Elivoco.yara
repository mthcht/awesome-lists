rule TrojanDownloader_Win32_Elivoco_A_2147646295_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Elivoco.A"
        threat_id = "2147646295"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Elivoco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {be 01 00 00 00 8b 45 f0 0f b7 44 70 fe 33 c3 89 45 dc 3b 7d dc 7c ?? 8b 45 dc 05 ff 00 00 00 2b c7 89 45 dc eb}  //weight: 20, accuracy: Low
        $x_20_2 = {85 c0 74 05 83 e8 04 8b 00 89 45 e4 33 f6 bb 00 01 00 00 8d 55 d0 8b 45 fc e8}  //weight: 20, accuracy: High
        $x_3_3 = "22CB13CA7FCB365CCA082CE711C2BB5487BD6688BD69978DBF679A82A" wide //weight: 3
        $x_3_4 = "FB2BC37593CD0C4EF62FC5B3AB48E21BC16094B" wide //weight: 3
        $x_3_5 = "6BCA5F8B3299CC0F311B1A0C0C6A" wide //weight: 3
        $x_3_6 = "B2579549F962F55C8F48FE29D77BE16C8CA55187" wide //weight: 3
        $x_2_7 = "TFrmLiveXNt" wide //weight: 2
        $x_2_8 = "window.location=\"https://www.%s.com.br/" wide //weight: 2
        $x_1_9 = "TZOracle9iPlainDriver" ascii //weight: 1
        $x_1_10 = "TZPostgreSQLSymbolState" ascii //weight: 1
        $x_1_11 = "FASA9PlainDriver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*) and 1 of ($x_2_*))) or
            ((2 of ($x_20_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

