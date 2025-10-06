rule Trojan_Win64_ShellCodeLoader_NWU_2147954064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeLoader.NWU!MTB"
        threat_id = "2147954064"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c1 e8 ?? ?? ?? ?? 48 83 7d ?? ?? 78 ?? 48 8b 85 ?? ?? ?? ?? 48 39 45 ?? 7c ?? 48 8b 85 ?? ?? ?? ?? 48 8d 50 ?? 48 8b 45 ?? 48 89 c1 e8 ?? ?? ?? ?? e9 ?? ?? ?? ?? 48 8b 95 ?? ?? ?? ?? 48 8b 45 ?? 48 01 d0 48 83 c0 ?? 0f b6 00 32 45 ?? 48 8b 4d}  //weight: 1, accuracy: Low
        $x_1_2 = "Evasive Shellcode Loader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

