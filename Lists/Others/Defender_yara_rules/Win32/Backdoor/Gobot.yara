rule Backdoor_Win32_Gobot_AM_2147599979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Gobot.AM"
        threat_id = "2147599979"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Gobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GhostBOT" ascii //weight: 1
        $x_1_2 = {8d 55 ec b8 01 00 00 00 e8 ?? ?? ff ff 8b 45 ec 50 a1 ?? ?? ?? ?? 8b 00 ff d0 85 c0 74 3f 68 88 13 00 00 a1 ?? ?? ?? ?? 8b 00 ff d0 8d 95 e8 fe ff ff b8 01 00 00 00 e8 ?? ?? ff ff 8b 95 e8 fe ff ff 8d 85 ec fe ff ff b9 ff 00 00 00 e8 ?? ?? ff ff 8d 85 ec fe ff ff e8 ?? ?? ff ff 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 e8 ?? ?? ff ff 50 a1 ?? ?? ?? ?? 8b 00 ff d0 3d 02 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

