rule TrojanDownloader_Win32_XFiles_MO_2147827643_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/XFiles.MO!MTB"
        threat_id = "2147827643"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "XFiles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "x.rune-spectrals.com/torrent/uploads" wide //weight: 1
        $x_1_2 = "{kgfvfffffl" ascii //weight: 1
        $x_1_3 = "f{{kc2" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

