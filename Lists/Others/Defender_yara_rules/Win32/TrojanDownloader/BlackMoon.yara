rule TrojanDownloader_Win32_BlackMoon_YA_2147741457_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/BlackMoon.YA!MTB"
        threat_id = "2147741457"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certutil.exe -urlcache -split -f http" ascii //weight: 1
        $x_1_2 = "BlackMoon RunTime Error" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

