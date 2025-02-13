rule TrojanDropper_Win32_Nelper_A_2147632555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Nelper.A"
        threat_id = "2147632555"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Nelper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 e9 03 03 c1 c6 00 4c c6 40 01 4f c6 40 02 47 8d 85 8c fe ff ff 50 e8 a7 00 00 00 59 3b c6 59 89 45 f8 75 04 8b c7 eb 7b 50 57 ff 75 f4 ff 75 fc e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b 08 83 c0 04 83 a4 8d e8 fa ff ff 00 3d 50 50 40 00 72 ec 8d 45 e8 c7 45 e8 07 00 00 00 50 8d 45 f4 50 6a 00 8d 85 e8 fa ff ff 6a 00 50 6a 13 6a 13}  //weight: 1, accuracy: High
        $x_1_3 = "Download.exe" ascii //weight: 1
        $x_1_4 = "TFRMPROXY" wide //weight: 1
        $x_1_5 = "TFRMDOWNLOAD" wide //weight: 1
        $x_1_6 = "url19:http://bbs.cnxp.com19:publisher-url.utf-819:http://bbs.cnxp.com15:publisher.utf-812:" ascii //weight: 1
        $x_1_7 = "(www.52bt.net).urleee4:name46:[2004.09.07]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

