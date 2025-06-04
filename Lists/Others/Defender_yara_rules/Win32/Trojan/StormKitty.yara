rule Trojan_Win32_StormKitty_DA_2147942813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StormKitty.DA!MTB"
        threat_id = "2147942813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 14 24 89 44 24 04 89 4c 24 08 e8 ?? ?? ?? ?? 8b 44 24 0c 8b 4c 24 10 89 04 24 89 4c 24 04 e8 ?? ?? ?? ?? 8b 44 24 08 8b 4c 24 14 8b 54 24 0c 8b 5c 24 10 8b 6c 24 18 89 84 24 9c 00 00 00 89 94 24 a0 00 00 00 89 9c 24 a4 00 00 00 89 8c 24 a8 00 00 00 89 ac 24 ac 00 00 00 83 c4 7c c3}  //weight: 3, accuracy: Low
        $x_2_2 = {0f b6 34 2b 31 d6 87 de 88 1c 28 87 de 45}  //weight: 2, accuracy: High
        $x_2_3 = "main.doubleDecrypt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

