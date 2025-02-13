rule TrojanDownloader_Win32_Dowritn_A_2147601065_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dowritn.A"
        threat_id = "2147601065"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dowritn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tmpdown32.dll" ascii //weight: 1
        $x_1_2 = "http://www.larapia.com/tmp/pdf.pdf" ascii //weight: 1
        $x_1_3 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en;) Gecko/30060309 Firefox/1.5.0.7" ascii //weight: 1
        $x_1_4 = "ed0350CE3494EBD45B2AE8A" ascii //weight: 1
        $x_1_5 = "SystemRoot" ascii //weight: 1
        $x_1_6 = "svchost.exe" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_8 = "WinExec" ascii //weight: 1
        $x_1_9 = {64 ff 30 64 89 20 68 ?? ?? 44 00 6a ff 6a 00 e8 ?? ?? fc ff 8b d8 85 db 74 0c e8 ?? ?? fc ff 3d b7 00 00 00 75 0d 53 e8 ?? ?? fc ff 33 c0 e8 ?? ?? fc ff 8d 55 ec b8 44 07 44 00 e8 ?? ?? fc ff 8b 55 ec b8 98 28 44 00 e8 ?? ?? fc ff 8d 45 e8 b9 58 07 44 00 8b 15 98 28 44 00 e8 ?? ?? fc ff 8b 45 e8 e8 ?? ?? fc ff 84 c0 0f 85 95 00 00 00 33 c0 55 68 ?? ?? 44 00 64 ff 30 64 89 20 8d 45 e4 b9 ?? ?? 44 00 8b 15 ?? ?? 44 00 e8 ?? ?? fc ff 8b 55 e4 a1 ?? ?? 44 00 e8 ?? ?? ff ff 6a 0a e8 ?? ?? fc ff 33 c0 5a 59 59 64 89 10 eb 0a}  //weight: 1, accuracy: Low
        $x_1_10 = {33 c0 55 68 ?? ?? 44 00 64 ff 30 64 89 20 6a 00 8d 45 e0 b9 ?? ?? 44 00 8b 15 98 28 44 00 e8 ?? ?? fc ff 8b 45 e0 e8 ?? ?? fc ff 50 e8 ?? ?? fc ff 6a 0a e8 ?? ?? fc ff 33 c0 5a 59 59 64 89 10 eb 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

