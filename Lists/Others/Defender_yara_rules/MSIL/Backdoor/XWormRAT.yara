rule Backdoor_MSIL_XWormRAT_B_2147849974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWormRAT.B!MTB"
        threat_id = "2147849974"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "2otdJCaHT2JzMes3gs1UVt3y7aP25LK0bJnBghJbDAl87QXBr7eW" ascii //weight: 2
        $x_2_2 = "GJvIqGTzI8Nhu7Whf9b11vLmfoqwZuaSAowYxbUKmpdQaFTlS8qb" ascii //weight: 2
        $x_2_3 = "QrFcEhnCD6Fg6KElDx4FSDbEHiaNxpUS6z16CtyFKlh8LuUuNoNu" ascii //weight: 2
        $x_2_4 = "ldoB5Rg8kSX1uNMNOHMoC0d9PcUXNqnFEhm0pmwuqDSazZTyG1Hy" ascii //weight: 2
        $x_1_5 = "Confuser.Core" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWormRAT_C_2147891893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWormRAT.C!MTB"
        threat_id = "2147891893"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 00 04 20 e8 03 00 00 d8 28}  //weight: 2, accuracy: High
        $x_1_2 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_3 = "set_Expect100Continue" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWormRAT_D_2147894577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWormRAT.D!MTB"
        threat_id = "2147894577"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 00 04 20 e8 03 00 00 d8 7e}  //weight: 2, accuracy: High
        $x_1_2 = "CheckRemoteDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWormRAT_F_2147898631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWormRAT.F!MTB"
        threat_id = "2147898631"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 55 02 dc 49 0f 00 00 00 fa 01 33 00 16 00 00 02 00 00 00 3e 00 00 00 36 00 00 00 4f 00 00 00 d9 00 00 00 c0}  //weight: 2, accuracy: High
        $x_1_2 = "CompressShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWormRAT_G_2147898632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWormRAT.G!MTB"
        threat_id = "2147898632"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 00 04 20 e8 03 00 00 d8 28}  //weight: 2, accuracy: High
        $x_2_2 = {25 26 14 14 14 17 28}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWormRAT_H_2147898782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWormRAT.H!MTB"
        threat_id = "2147898782"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 00 04 20 e8 03 00 00 d8 38}  //weight: 2, accuracy: High
        $x_2_2 = {20 b8 0b 00 00 20 10 27 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWormRAT_SP_2147899641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWormRAT.SP!MTB"
        threat_id = "2147899641"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {73 0b 00 00 06 13 05 73 ?? ?? ?? 0a 13 06 11 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 13 07 11 04 14 18 8d ?? ?? ?? 01 13 0a 11 0a 16 72 ?? ?? ?? 70 a2 11 0a 17 11 07 a2 11 0a 6f ?? ?? ?? 0a 26 11 05 13 09 de 3f}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWormRAT_I_2147900131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWormRAT.I!MTB"
        threat_id = "2147900131"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 04 13 14 7e ?? 00 00 04 13 0b 7e ?? 00 00 04 20 e8 03 00 00 d8 1f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWormRAT_HJAA_2147904865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWormRAT.HJAA!MTB"
        threat_id = "2147904865"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "85wQWaGMMb6Mo0+H1yc2H+RfkOv2ih34txt4rmMobVk=" wide //weight: 2
        $x_2_2 = "kPmvfIyH1urDMB7qqMQHMA==" wide //weight: 2
        $x_2_3 = "Gw5rVSFJxc+t+F2aCe4P8g==" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWormRAT_J_2147904895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWormRAT.J!MTB"
        threat_id = "2147904895"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 20 e8 03 00 00 d8 28}  //weight: 2, accuracy: High
        $x_2_2 = {0a 0b 07 14 73 ?? ?? ?? 0a 20 10 27 00 00 20 98 3a 00 00 6f}  //weight: 2, accuracy: Low
        $x_2_3 = {07 6c 23 00 00 00 00 00 00 d0 41 5b 13 04 12 04 28}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWormRAT_K_2147904908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWormRAT.K!MTB"
        threat_id = "2147904908"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "(*.hta)|*.hta" wide //weight: 2
        $x_2_2 = "\\s*[\\w\\.\\(\\)]+\\s*(" wide //weight: 2
        $x_2_3 = "/target:winexe /platform:anycpu /optimize" wide //weight: 2
        $x_2_4 = "/c cmdkey /generic" wide //weight: 2
        $x_2_5 = "HKEY_CURRENT_USER\\SOFTWARE\\XWorm" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

