rule TrojanDownloader_Win32_Alien_AYA_2147926812_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Alien.AYA!MTB"
        threat_id = "2147926812"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Alien"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "lvmay.top" ascii //weight: 2
        $x_1_2 = "ddjm.top" ascii //weight: 1
        $x_1_3 = "Q3JlYXRlUHJvY2Vzc0E=" ascii //weight: 1
        $x_1_4 = "%s\\temp\\%d.bak" ascii //weight: 1
        $x_1_5 = "Users/Public/WINWORD.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

