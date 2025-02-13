rule TrojanDownloader_MSIL_Muxif_A_2147694674_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Muxif.A"
        threat_id = "2147694674"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Muxif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 16 00 00 0a 6f 17 00 00 0a ?? 28 15 00 00 0a 72 ?? 00 00 70 06 72 ?? 00 00 70 28 16 00 00 0a 28 18 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "qwe123.exe" ascii //weight: 1
        $x_1_3 = "AutoRun" ascii //weight: 1
        $x_1_4 = "filehereload2.ru/" wide //weight: 1
        $x_1_5 = "win32_logicaldisk.deviceid=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

