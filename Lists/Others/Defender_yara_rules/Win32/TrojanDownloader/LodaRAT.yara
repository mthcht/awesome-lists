rule TrojanDownloader_Win32_LodaRAT_RDA_2147838103_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/LodaRAT.RDA!MTB"
        threat_id = "2147838103"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "LodaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%windir%\\svhost.exe" wide //weight: 1
        $x_1_2 = "//app.csvhost.info/loader/spoolsv.tmp" wide //weight: 1
        $x_2_3 = {0f b6 04 39 33 c6 25 ff 00 00 00 c1 ee 08 33 b4 85 fc fb ff ff 41}  //weight: 2, accuracy: High
        $x_2_4 = {0f b6 c2 03 c8 81 e1 ff 00 00 00 0f b6 84 0d fc fe ff ff 8b 8d f4 fe ff ff 30 44 39 ff}  //weight: 2, accuracy: High
        $x_1_5 = "Global\\3pc6RWOgectGTFqCowxjeGy3XIGPtLwNrsr2zDctYD4hAU5pj4GW7rm8gHrHyTB6" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

