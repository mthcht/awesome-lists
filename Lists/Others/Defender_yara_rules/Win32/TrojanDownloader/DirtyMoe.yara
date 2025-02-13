rule TrojanDownloader_Win32_DirtyMoe_A_2147851369_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/DirtyMoe.A!MTB"
        threat_id = "2147851369"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "DirtyMoe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d8 85 db 7e ?? 8b 4d fc 8d 85 ?? ?? ?? ?? 53 50 a1 ?? ?? ?? ?? 03 c1 50 e8 83 01 00 00 01 5d fc 83 c4 ?? 81 7d fc ?? ?? ?? ?? 74 ?? 6a 00 8d 85 ?? ?? ?? ?? 57 50 ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

