rule TrojanDownloader_VBS_CoinMiner_BT_2147727354_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:VBS/CoinMiner.BT!bit"
        threat_id = "2147727354"
        type = "TrojanDownloader"
        platform = "VBS: Visual Basic scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ftphosting.pw/" ascii //weight: 1
        $x_1_2 = "RANDOM=CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_3 = "RANDOM=CreateObject(\"WinHttp.WinHttpRequest.5.1\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

