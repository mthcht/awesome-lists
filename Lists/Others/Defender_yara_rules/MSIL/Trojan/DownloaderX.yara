rule Trojan_MSIL_DownloaderX_A_2147783885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DownloaderX.A!ibt"
        threat_id = "2147783885"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DownloaderX"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "schtasks /create /tn \\" ascii //weight: 4
        $x_4_2 = "/st 00:00 /du 9999:59 /sc once /ri 1 /f" ascii //weight: 4
        $x_4_3 = {63 00 68 00 6f 00 69 00 63 00 65 00 20 00 2f 00 43 00 20 00 59 00 20 00 2f 00 4e 00 20 00 2f 00 44 00 20 00 59 00 20 00 2f 00 54 00 [0-6] 26 00 20 00 44 00 65 00 6c 00}  //weight: 4, accuracy: Low
        $x_4_4 = {63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 [0-6] 26 20 44 65 6c}  //weight: 4, accuracy: Low
        $x_1_5 = "XLoader" ascii //weight: 1
        $x_1_6 = "Logger" ascii //weight: 1
        $x_1_7 = "SelfDelete" ascii //weight: 1
        $x_1_8 = "DownloadFile" ascii //weight: 1
        $x_1_9 = "DropperV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 2 of ($x_1_*))) or
            ((4 of ($x_4_*))) or
            (all of ($x*))
        )
}

