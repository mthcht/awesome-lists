rule Worm_Win32_NgrBot_GXZ_2147903453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/NgrBot.GXZ!MTB"
        threat_id = "2147903453"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "NgrBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {23 d8 88 9d ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? 0f b6 8d ?? ?? ?? ?? 8d 54 08 ?? 88 55 ?? 0f b6 45 ?? 83 c0 46 0f b7 4d ?? 33 c8 66 89 4d ?? 0f b7 55 ?? 0f b6 85 ?? ?? ?? ?? 2b d0 0f b6 8d ?? ?? ?? ?? 8d 54 0a ?? 0f b6 85 ?? ?? ?? ?? 2b d0 88 95 ?? ?? ?? ?? 0f b6 8d ?? ?? ?? ?? 0f b6 55 ?? 3b ca}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

