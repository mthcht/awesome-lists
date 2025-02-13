rule TrojanDownloader_Win32_WebDown_H_2147610325_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/WebDown.H"
        threat_id = "2147610325"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "WebDown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 24 20 40 00 6a 00 6a 00 e8 53 00 00 00 68 00 01 00 00 68 ?? ?? 40 00 6a 00 e8 30 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

