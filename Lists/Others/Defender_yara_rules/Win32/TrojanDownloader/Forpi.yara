rule TrojanDownloader_Win32_Forpi_A_2147645590_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Forpi.A"
        threat_id = "2147645590"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Forpi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PPTV(pplive)_for" ascii //weight: 1
        $x_1_2 = "\\PPLive" ascii //weight: 1
        $x_1_3 = "download.pplive.com" ascii //weight: 1
        $x_1_4 = "Microsoft\\Internet Explorer\\Quick Launch\\PPTV" ascii //weight: 1
        $x_3_5 = {8b c0 53 33 db 6a 00 e8 ?? ?? ?? ?? 83 f8 07 75 1c 6a 01 e8 ?? ?? ?? ?? 25 00 ff 00 00 3d 00 0d 00 00 74 07 3d 00 04 00 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Forpi_B_2147646604_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Forpi.B"
        threat_id = "2147646604"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Forpi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://u.pptv7.com/tj1/" wide //weight: 1
        $x_1_2 = "clsWaitableTimer" ascii //weight: 1
        $x_1_3 = {50 f3 ab b9 4a 00 00 00 8d bc 24 ?? ?? 00 00 f3 ab b9 4a 00 00 00 8d 7c 24 14 f3 ab 6a 0f e8}  //weight: 1, accuracy: Low
        $x_1_4 = {50 6a 00 8d 45 d4 52 50 ff d6 8b 4d dc 50 8d 55 d8 51 52 ff d6 50 53 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = "tj.wanleishi.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

