rule TrojanDownloader_Win32_Gletno_A_2147682580_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gletno.A"
        threat_id = "2147682580"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gletno"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d3 50 ff d6 8b f8 8b 45 ?? 40 8b 00 89 45 ?? 8b c7 40 8b 00 89 45 ?? 8d 45 ?? 50 6a 40 6a 05 57 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

