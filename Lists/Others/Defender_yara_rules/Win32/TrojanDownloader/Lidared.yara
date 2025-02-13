rule TrojanDownloader_Win32_Lidared_B_2147706418_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lidared.B"
        threat_id = "2147706418"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lidared"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/tongji.php?userid=%s&mac=%s&iddd=%s&key=%s&a=%s" wide //weight: 2
        $x_2_2 = "006czSTKjw1evlzzhdo2wg3085064e83.gif" wide //weight: 2
        $x_1_3 = "papa-sam.exe" wide //weight: 1
        $x_1_4 = "LastBootUpTime" wide //weight: 1
        $x_1_5 = "noting" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

