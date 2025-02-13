rule TrojanDownloader_Win32_Xabduu_ARAA_2147906262_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Xabduu.ARAA!MTB"
        threat_id = "2147906262"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Xabduu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Meteorite Downloader" wide //weight: 2
        $x_2_2 = "regwrite" wide //weight: 2
        $x_2_3 = "wscript.shell" wide //weight: 2
        $x_2_4 = "modMain" ascii //weight: 2
        $x_2_5 = "urlmon" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

