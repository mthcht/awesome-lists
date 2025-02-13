rule TrojanDownloader_Win32_Pilrurl_A_2147610231_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pilrurl.A"
        threat_id = "2147610231"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pilrurl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1b 04 00 04 78 ff 34 6c 78 ff f5 01 00 00 80 0a}  //weight: 2, accuracy: High
        $x_2_2 = "KVMonXP.kxp,KvXP.kxp" wide //weight: 2
        $x_2_3 = "KAV32.EXE,KATMain.EXE" wide //weight: 2
        $x_1_4 = "\\IELOCK.VBP" wide //weight: 1
        $x_1_5 = "Start Page" wide //weight: 1
        $x_1_6 = ":prurl" wide //weight: 1
        $x_1_7 = "TerminateProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

