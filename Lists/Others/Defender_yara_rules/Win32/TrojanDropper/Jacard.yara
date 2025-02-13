rule TrojanDropper_Win32_Jacard_GXH_2147923963_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Jacard.GXH!MTB"
        threat_id = "2147923963"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Jacard"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 04 24 30 44 24 01 8d 54 24 01 8b c5 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 43 4e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

