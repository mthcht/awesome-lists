rule TrojanDownloader_Win32_Radtheif_AHB_2147965716_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Radtheif.AHB!MTB"
        threat_id = "2147965716"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Radtheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = "C:\\Windows\\Systenm.exe" ascii //weight: 30
        $x_10_2 = "C:\\Windows\\1.bin" ascii //weight: 10
        $x_20_3 = "C:\\Windows\\awesomium.dll" ascii //weight: 20
        $x_40_4 = {8d 4d cc c7 45 fc 00 00 00 00 e8 ?? ?? ?? ?? 6a 05 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 8b 55 cc 85 d2 74}  //weight: 40, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

