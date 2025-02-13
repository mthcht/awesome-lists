rule TrojanDownloader_MSIL_Downcoin_B_2147691579_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Downcoin.B"
        threat_id = "2147691579"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downcoin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "filehostonline.com/files/25/bitcoin-miner.exe" wide //weight: 10
        $x_10_2 = "winminer.exe" wide //weight: 10
        $x_1_3 = "windefender.exe" wide //weight: 1
        $x_1_4 = "winsrv.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

