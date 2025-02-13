rule Backdoor_Win32_AveMaria_GKM_2147776988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/AveMaria.GKM!MTB"
        threat_id = "2147776988"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c2 01 89 55 ?? 8b 45 ?? 3b 85 ?? ?? ?? ?? 7d ?? 8b 45 ?? 99 f7 bd ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 0f be 11 8b 85 ?? ?? ?? ?? 0f be 4c 05 ?? 33 d1 8b 45 ?? 03 45 ?? 88 10 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

