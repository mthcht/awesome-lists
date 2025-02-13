rule Trojan_Win32_DorkBot_DSK_2147749725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DorkBot.DSK!MTB"
        threat_id = "2147749725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DorkBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 ec 8b 4d dc 0f b7 14 41 0f be 45 ab 0f af 45 d8 0f be 4d ab 8b 75 d8 2b f1 33 c6 03 d0 88 55 cf}  //weight: 2, accuracy: High
        $x_2_2 = {0f b6 08 0f be 95 ?? ?? ff ff 0f af 95 ?? ?? ff ff 0f be 85 ?? ?? ff ff 8b b5 ?? ?? ff ff 2b f0 33 d6 03 ca 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ff ff 88 0a}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 4d cc 0f b6 91 ?? ?? ?? ?? c7 45 c4 ?? ?? ?? ?? 8b 45 d4 0f b6 88 ?? ?? ?? ?? 33 ca 8b 55 d4 89 4d ac 88 8a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_DorkBot_DU_2147752886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DorkBot.DU"
        threat_id = "2147752886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DorkBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 57 51 8b 74 24 14 8b 7c 24 10 8b 4c 24 18 f3 a4 59 5f 5e c2 0c 00 cc cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DorkBot_RPA_2147833440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DorkBot.RPA!MTB"
        threat_id = "2147833440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DorkBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c0 01 33 45 f0 03 d0 88 55 ff 8b 4d e8 8a 55 ff 88 94 0d e0 ed ff ff 8b 45 e8 83 c0 01 89 45 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DorkBot_RDA_2147840147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DorkBot.RDA!MTB"
        threat_id = "2147840147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DorkBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 d1 29 c1 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af c2 29 c1 89 c8 89 c2 8b 45 dc 01 d0 0f b6 00 31 f0 88 03}  //weight: 2, accuracy: Low
        $x_1_2 = "LdrFindResource_U" ascii //weight: 1
        $x_1_3 = "LdrAccessResource" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "sc.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DorkBot_RPX_2147853492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DorkBot.RPX!MTB"
        threat_id = "2147853492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DorkBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 dc 01 45 f8 8b 4d f0 8b 45 f4 8b d7 d3 ea 03 c7 03 55 d8 33 d0 31 55 f8 8b 45 f8 29 45 ec 8b 45 e0 29 45 f4 ff 4d e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DorkBot_A_2147891942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DorkBot.A!MTB"
        threat_id = "2147891942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DorkBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b ca 88 4d f9 0f b6 45 fe 83 e0 ?? c1 e0 04 0f b6 4d ff 83 e1 ?? c1 f9 02 0b c1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DorkBot_RPY_2147908493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DorkBot.RPY!MTB"
        threat_id = "2147908493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DorkBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( \"F\" & \"i\" & \"l\" & \"e\" & \"R\" & \"e\" & \"a\" & \"d" wide //weight: 1
        $x_1_2 = "EXECUTE ( \"D\" & \"l\" & \"l\" & \"C\" & \"a\" & \"l\" & \"l\" & \"A\" & \"d\" & \"d\" & \"r\" & \"e\" & \"s\" & \"s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

