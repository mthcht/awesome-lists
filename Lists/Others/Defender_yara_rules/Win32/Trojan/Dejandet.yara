rule Trojan_Win32_Dejandet_A_2147763088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dejandet.A!MTB"
        threat_id = "2147763088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dejandet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b f0 8a 40 02 84 c0 75 ?? 8b 46 68 83 e0 70 85 c0 75 0c 8b 46 18 8b 40 10 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dejandet_G_2147763090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dejandet.G!MTB"
        threat_id = "2147763090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dejandet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b f0 8a 40 02 84 c0 75 [0-112] 8b 46 68 83 e0 70 85 c0 75 ?? 8b 46 18 8b 40 10 85 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dejandet_I_2147763091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dejandet.I!MTB"
        threat_id = "2147763091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dejandet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 01 08 83 c0 02 66 83 38 00 75 ef 40 00 c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? [0-16] b9 ?? 00 00 00 66 01 08 83 c0 02 66 83 38 00 75 ef}  //weight: 1, accuracy: Low
        $x_1_2 = {66 01 08 83 c0 02 66 83 38 00 75 ef 40 00 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? [0-16] b9 ?? 00 00 00 66 01 08 83 c0 02 66 83 38 00 75 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dejandet_F_2147768566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dejandet.F!MTB"
        threat_id = "2147768566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dejandet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 68 c1 e8 08 a8 01 75 ?? ff 75 08 ff 15 1c f0 40 00 50 ff 15 20 f0 40 00 ff 75 08 e8 4f 00 00 00 59 ff 75 08 ff 15 04 f0 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

