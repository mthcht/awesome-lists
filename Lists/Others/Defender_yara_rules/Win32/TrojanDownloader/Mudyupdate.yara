rule TrojanDownloader_Win32_Mudyupdate_2147734625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mudyupdate"
        threat_id = "2147734625"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mudyupdate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\MWP\\Processed\\Start.B.1\\Project1.vbp" wide //weight: 1
        $x_1_2 = "exe.rerolpxE" wide //weight: 1
        $x_1_3 = "\\Window Desktop Manager\\wdm.exe" wide //weight: 1
        $x_1_4 = "MSXML2.XMLHTTP" wide //weight: 1
        $x_1_5 = "ataDppA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

