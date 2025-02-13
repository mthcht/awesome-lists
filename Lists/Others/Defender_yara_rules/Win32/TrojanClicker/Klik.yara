rule TrojanClicker_Win32_Klik_2147615376_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Klik"
        threat_id = "2147615376"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Klik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "102"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {54 61 62 4f 72 64 65 72 [0-3] 54 65 78 74 [0-2] 68 74 74 70 3a 2f 2f [0-16] 75 70 6c 6f 61 64 65 72}  //weight: 100, accuracy: Low
        $x_1_2 = "supertds.com" ascii //weight: 1
        $x_1_3 = "klikiRandomizer = " ascii //weight: 1
        $x_1_4 = "WebBrowser1DownloadComplete" ascii //weight: 1
        $x_1_5 = "Klikat ne budem! Uze est" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

