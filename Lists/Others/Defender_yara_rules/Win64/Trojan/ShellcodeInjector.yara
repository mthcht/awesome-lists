rule Trojan_Win64_ShellcodeInjector_ARA_2147967965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInjector.ARA!MTB"
        threat_id = "2147967965"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4c 39 c2 74 2a 48 89 d1 48 89 d0 83 e0 1f 83 e1 0f 41 8a 0c 0a 41 32 0c 03 89 d0 32 0c 13 0f af c6 83 c0 0d 31 c8 41 88 04 11 48 ff c2 eb d1}  //weight: 2, accuracy: High
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "RegSetValueExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

