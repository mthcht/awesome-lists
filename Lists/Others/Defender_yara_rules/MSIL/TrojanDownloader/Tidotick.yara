rule TrojanDownloader_MSIL_Tidotick_A_2147695870_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tidotick.A"
        threat_id = "2147695870"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tidotick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Timer2_Tick" ascii //weight: 1
        $x_1_2 = {00 0a 00 02 6f ?? 00 00 06 16 6f ?? 00 00 0a 00 72 ?? ?? 00 70 0a 1d 28 ?? 00 00 0a 72 ?? ?? 00 70 28 ?? 00 00 0a 0b 07 28 ?? 00 00 0a 0c 08 2c 07 07 28 ?? 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

