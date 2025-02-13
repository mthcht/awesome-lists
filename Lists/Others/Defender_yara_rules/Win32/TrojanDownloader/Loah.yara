rule TrojanDownloader_Win32_Loah_2147593813_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Loah"
        threat_id = "2147593813"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Loah"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.haol23.net/?a04//" ascii //weight: 1
        $x_1_2 = "{871C5380-42A0-1069-A2EA-08002B30309D}" ascii //weight: 1
        $x_1_3 = "{%08lX-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}" ascii //weight: 1
        $x_1_4 = "CurCode" ascii //weight: 1
        $x_1_5 = "%4.4d%2.2d%2.2d" ascii //weight: 1
        $x_1_6 = "%02X%02X%02X%02X%02X%02X" ascii //weight: 1
        $x_2_7 = "QqHelperJ.dll" ascii //weight: 2
        $x_2_8 = "http://update.microfsot.cn/dl/1.dat?%s" ascii //weight: 2
        $x_1_9 = {bf 01 00 00 80 57 ff d6 6a 04 8d 45 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

