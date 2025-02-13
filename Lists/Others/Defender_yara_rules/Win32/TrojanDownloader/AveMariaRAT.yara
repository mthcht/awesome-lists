rule TrojanDownloader_Win32_AveMariaRAT_A_2147848923_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AveMariaRAT.A!MTB"
        threat_id = "2147848923"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell.exe -inputformat none -outputformat none -NonInteractive -Command" wide //weight: 2
        $x_2_2 = "Add-MpPreference -ExclusionPath C:\\Users\\Public" wide //weight: 2
        $x_2_3 = "MSXML2.XMLHTTP" wide //weight: 2
        $x_2_4 = "ADODB.Stream" wide //weight: 2
        $x_2_5 = "responseBody" wide //weight: 2
        $x_2_6 = "SaveToFile" wide //weight: 2
        $x_2_7 = "WScript.Shell" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

