rule Backdoor_Win32_SysJoker_AA_2147810764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/SysJoker.AA!MTB"
        threat_id = "2147810764"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "SysJoker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 0c 11 30 88 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 c8 0f b6 4c 11 ?? 30 88 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 c8 0f b6 4c 11 ?? 30 88 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 c8 0f b6 4c 11 ?? 30 88 ?? ?? ?? ?? 83 c0 ?? 83 f8 ?? 0f 8c}  //weight: 2, accuracy: Low
        $x_1_2 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkfNl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

