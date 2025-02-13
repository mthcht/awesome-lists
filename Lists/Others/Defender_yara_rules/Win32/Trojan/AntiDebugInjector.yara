rule Trojan_Win32_AntiDebugInjector_2147744355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AntiDebugInjector!MTB"
        threat_id = "2147744355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AntiDebugInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c9 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 31 d2 39 c1 0f 94 c2 8d 4c 11 01 81 f9 ?? ?? ?? ?? 7c ed 40 3d ?? ?? ?? ?? 75 d5 [0-48] 50 6a 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

