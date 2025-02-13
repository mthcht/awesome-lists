rule TrojanDownloader_Win32_Convagent_AW_2147834830_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Convagent.AW!MTB"
        threat_id = "2147834830"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 45 98 8b 45 98 8a 08 88 4d b8 0f be 45 b8 99 33 85 [0-4] 8b 55 98 88 02 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

