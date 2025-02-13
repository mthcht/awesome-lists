rule TrojanDownloader_Win32_Tnega_ARA_2147894581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tnega.ARA!MTB"
        threat_id = "2147894581"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 44 3d e8 6a 01 8d 4d f0 51 68 ?? ?? ?? ?? 88 45 f0 e8 ?? ?? ?? ?? 88 44 3d e8 47 83 ff 04 7c df}  //weight: 2, accuracy: Low
        $x_2_2 = "aHR0cDovL2R3LjljaWRjLmNuL2J5ZTAwMS5iaW4=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

