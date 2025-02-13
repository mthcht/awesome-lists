rule TrojanDownloader_Win32_Nekotimed_A_2147648268_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nekotimed.A"
        threat_id = "2147648268"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nekotimed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "dm.demisetoken.com:86/log.aspx?" ascii //weight: 4
        $x_4_2 = "/xn.bis" ascii //weight: 4
        $x_4_3 = "@wen#%%%6n" ascii //weight: 4
        $x_4_4 = {5b 6d 61 69 6e 5d 00 [0-21] 2e 70 68 70 00}  //weight: 4, accuracy: Low
        $x_4_5 = "dm.caravel2.com:86/log.aspx?" ascii //weight: 4
        $x_4_6 = {83 7d f0 10 8b 45 dc 73 03 8d 45 dc ff 75 ec 50 8d 85 80 f7 ff ff 50 e8}  //weight: 4, accuracy: High
        $x_2_7 = "winio.sys" ascii //weight: 2
        $x_2_8 = "Computer ID_______________________: %d" ascii //weight: 2
        $x_2_9 = "win_%u" ascii //weight: 2
        $x_2_10 = "mid=%s&av=%s&sn=%s" ascii //weight: 2
        $x_2_11 = "F02810BB9D466D}" ascii //weight: 2
        $x_2_12 = "soft_lock" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 5 of ($x_2_*))) or
            ((4 of ($x_4_*) and 3 of ($x_2_*))) or
            ((5 of ($x_4_*) and 1 of ($x_2_*))) or
            ((6 of ($x_4_*))) or
            (all of ($x*))
        )
}

