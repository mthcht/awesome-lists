rule Trojan_Win32_ShellLoader_SX_2147961547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellLoader.SX!MTB"
        threat_id = "2147961547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 8b 1c b8 03 de 8b f2 8a 0b 6b f6 7f 0f be c1 03 f0 43 84 c9 75 f1 8b 5d f4 89 75 f0 8b 75 f8 3b 5d f0 74 08 47 3b 7d ec 72 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellLoader_SX_2147961547_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellLoader.SX!MTB"
        threat_id = "2147961547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8b 4d 08 03 4d fc 0f be 51 01 0f be 45 0c 33 d0 c1 e2 08 8b 4d 08 03 4d fc 0f be 01 0f be 4d 0c 33 c1 0b d0}  //weight: 20, accuracy: High
        $x_10_2 = {c7 45 b0 05 40 00 80 c6 45 bb a2 c6 45 bc e1 c6 45 bd a2 c6 45 be 98 c6 45 bf a2 c6 45 c0 fe c6 45 c1 a2 c6 45 c2 f2 c6 45 c3 a2 c6 45 c4 d0 c6 45 c5 a2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

