rule Trojan_Win32_Parallax_PA_2147750068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Parallax.PA!MTB"
        threat_id = "2147750068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Parallax"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {57 8b 7c 24 10 33 c0 85 ff 7e 4c 53 8b 5c 24 10 56 8b 74 24 10 2b de eb 07 8d a4 24 00 00 00 00 8b 0c 85 ?? ?? ?? 00 33 0c 33 89 0e 85 c0 74 1f 8b 15 ?? ?? ?? 00 33 15 ?? ?? ?? 00 0f bf 0d ?? ?? ?? 00 3b ca 7e 07 c6 05 ?? ?? ?? 00 ac 40 83 c6 04 4f 75 cb}  //weight: 10, accuracy: Low
        $x_1_2 = {56 66 c7 45 ?? 6f 63 66 c7 45 ?? 41 6c 66 c7 45 ?? 72 74 c6 45 ?? 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Parallax_PB_2147750998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Parallax.PB!MTB"
        threat_id = "2147750998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Parallax"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 8b 55 f8 8b 0c 90 8b 5d 14 8b 45 fc 33 0c 83 8b 55 08 8b 45 f8 89 0c 82 8b 15 ?? ?? ?? ?? 3b 15 ?? ?? ?? ?? 8b 4d ?? 49 3b 4d fc 75 07 33 c0 89 45 fc eb 2c 0f be 15 ?? ?? ?? ?? 3b 15 ?? ?? ?? ?? 7f 0a c7 05 ?? ?? ?? ?? ?? 00 00 00 80 3d ?? ?? ?? ?? 00 74 07 80 3d ?? ?? ?? ?? 00 ff 45 fc ff 45 f8 8b 4d f8 3b 4d 10 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Parallax_PC_2147752195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Parallax.PC!MTB"
        threat_id = "2147752195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Parallax"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f3 00 57 e0 05 8b 44 24 14 05 00 10 00 00 83 ec 04 54 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {31 1f 83 c7 04 83 e9 04 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {83 f9 00 0f 8f ?? ?? 00 00 5f bb 20 c6 e7 05 e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {b9 78 00 00 00 b8 23 00 00 00 03 c8 2b c1 83 c1 75 83 c0 12 8b c0 8b c0 8b c0 8b c8 8b c8 8b c9 8b c9 a8 23}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

