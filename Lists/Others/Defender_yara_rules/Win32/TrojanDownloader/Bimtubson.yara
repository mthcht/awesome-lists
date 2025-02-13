rule TrojanDownloader_Win32_Bimtubson_A_2147636892_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bimtubson.A"
        threat_id = "2147636892"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bimtubson"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/log/ver.asp?ID=0" ascii //weight: 1
        $x_1_2 = "Refresh\" CONTENT=\"0; URL=%0:s\">" ascii //weight: 1
        $x_1_3 = "&&&&&&sid&rune&t.ti&&&d&&" ascii //weight: 1
        $x_1_4 = {8a 10 80 ea 0a 74 05 80 ea 03 75 03 c6 00 00 40 4b 75 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Bimtubson_B_2147645347_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bimtubson.B"
        threat_id = "2147645347"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bimtubson"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Nullsoft Install System" ascii //weight: 1
        $x_1_2 = {65 78 65 63 2e 64 6c 6c ?? ?? ?? ?? 5c 69 65 70 73 65 74 75 70 2e 65 78 65 00 6f 70 65 6e ?? ?? ?? ?? 5c 53 63 61 63 68 65 2e 65 78 65 00 2d 70}  //weight: 1, accuracy: Low
        $x_1_3 = {53 63 61 63 68 65 2e 65 78 65 00 33 30 30 30 00 6f 70 65 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

