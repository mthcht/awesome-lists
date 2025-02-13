rule Backdoor_Win32_Smokeloader_UA_2147824163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Smokeloader.UA!MTB"
        threat_id = "2147824163"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 08 81 f1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 88 0a eb 43 00 8b 55 ?? 83 c2 ?? 89 55 ?? 83 7d ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

