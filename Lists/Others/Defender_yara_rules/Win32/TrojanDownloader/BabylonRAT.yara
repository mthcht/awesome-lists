rule TrojanDownloader_Win32_BabylonRAT_A_2147915194_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/BabylonRAT.A!MTB"
        threat_id = "2147915194"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "BabylonRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "do @curl -o" ascii //weight: 2
        $x_2_2 = "for /f \"delims=\" %i in ('curl -s" ascii //weight: 2
        $x_4_3 = "powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

