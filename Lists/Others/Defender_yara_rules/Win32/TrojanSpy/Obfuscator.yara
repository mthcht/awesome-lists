rule TrojanSpy_Win32_Obfuscator_UK_2147755425_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Obfuscator.UK!MTB"
        threat_id = "2147755425"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 33 c9 c7 45 ?? ?? ?? ?? ?? 85 f6 74 1b 8a 81 ?? ?? ?? ?? 30 82 ?? ?? ?? ?? 83 f9 ?? [0-2] 33 c9 [0-2] 41 42 3b d6 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Obfuscator_KG_2147755429_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Obfuscator.KG!MTB"
        threat_id = "2147755429"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 f7 bd 78 ff ff ff 89 95 6c ff ff ff 8b 55 88 03 55 94 0f be 02 8b 8d 6c ff ff ff 0f be 54 0d 98 33 c2 8b 4d 88 03 4d 94 88 01 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

