rule TrojanDownloader_Win32_Discord_ARAQ_2147908938_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Discord.ARAQ!MTB"
        threat_id = "2147908938"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Discord"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "/Powershell-Token-Grabber/" ascii //weight: 4
        $x_4_2 = "-ExecutionPolicy Unrestricted -Force" ascii //weight: 4
        $x_4_3 = "bypass -WindowStyle hidden -file" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

