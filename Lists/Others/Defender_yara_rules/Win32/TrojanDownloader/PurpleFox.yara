rule TrojanDownloader_Win32_PurpleFox_A_2147894589_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/PurpleFox.A!MTB"
        threat_id = "2147894589"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "PurpleFox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {57 ff d6 68 ?? ?? ?? ?? 8b f8 ff 15 ?? ?? ?? ?? ff d6 2b c7 5f 3d ?? ?? ?? ?? 5e 0f 9c c0}  //weight: 2, accuracy: Low
        $x_2_2 = {57 ff d6 bf ?? ?? ?? ?? 8b d8 57 ff 15 ?? ?? ?? ?? ff d6 2b c3 3b c7 5f 5e 5b 0f 9c c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

