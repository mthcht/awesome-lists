rule TrojanDownloader_Win32_Vbloadolf_A_2147711152_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vbloadolf.A"
        threat_id = "2147711152"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbloadolf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Set bStrm = CreateObject" ascii //weight: 1
        $x_1_2 = "wscript.exe C:\\TEMP\\33terfd.vbs" wide //weight: 1
        $x_1_3 = "/box/archivo.exe" ascii //weight: 1
        $x_1_4 = {53 61 76 65 54 6f 46 69 6c 65 [0-48] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_2_5 = "\\EOF\\Alfredo\\Downloader\\Project1.vbp" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

