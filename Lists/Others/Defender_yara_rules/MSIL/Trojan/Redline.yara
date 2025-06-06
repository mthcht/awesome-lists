rule Trojan_MSIL_Redline_GC_2147776761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GC!MTB"
        threat_id = "2147776761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "@C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AddInProcess32.exe" wide //weight: 10
        $x_5_2 = "Expect100Continue" ascii //weight: 5
        $x_5_3 = "FromBase64String" ascii //weight: 5
        $x_1_4 = "e_magic" ascii //weight: 1
        $x_1_5 = "e_lfanew" ascii //weight: 1
        $x_1_6 = "CallSiteBinder" ascii //weight: 1
        $x_1_7 = "hProcess" ascii //weight: 1
        $x_1_8 = "VirtualAddress" ascii //weight: 1
        $x_1_9 = "SystemNetworkCredential" ascii //weight: 1
        $x_1_10 = "procName" ascii //weight: 1
        $x_1_11 = "fileName" ascii //weight: 1
        $x_1_12 = "AddressOfEntryPoint" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Redline_GD_2147778577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GD!MTB"
        threat_id = "2147778577"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 [0-20] 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 [0-20] 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 [0-20] 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 [0-20] 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 [0-20] 33 00 31 00 39 00 5c 00 41 00 64 00 64 00 49 00 6e 00 [0-20] 72 00 6f 00 63 00 65 00 73 00 73 00 33 00 32 00 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_5_2 = "Expect100Continue" ascii //weight: 5
        $x_5_3 = "FromBase64String" ascii //weight: 5
        $x_1_4 = "e_magic" ascii //weight: 1
        $x_1_5 = "e_lfanew" ascii //weight: 1
        $x_1_6 = "CallSiteBinder" ascii //weight: 1
        $x_1_7 = "hProcess" ascii //weight: 1
        $x_1_8 = "VirtualAddress" ascii //weight: 1
        $x_1_9 = "Credential" ascii //weight: 1
        $x_1_10 = "procName" ascii //weight: 1
        $x_1_11 = "fileName" ascii //weight: 1
        $x_1_12 = "AddressOfEntryPoint" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Redline_GE_2147779092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GE!MTB"
        threat_id = "2147779092"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 [0-20] 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 [0-20] 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 [0-20] 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 [0-20] 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 [0-20] 33 00 31 00 39 00 5c 00 41 00 64 00 64 00 49 00 6e 00 [0-20] 72 00 6f 00 63 00 65 00 73 00 73 00 33 00 32 00 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_5_2 = ".NPROTECTET" ascii //weight: 5
        $x_5_3 = "FromBase64String" ascii //weight: 5
        $x_1_4 = "e_magic" ascii //weight: 1
        $x_1_5 = "e_lfanew" ascii //weight: 1
        $x_1_6 = "CallSiteBinder" ascii //weight: 1
        $x_1_7 = "hProcess" ascii //weight: 1
        $x_1_8 = "VirtualAddress" ascii //weight: 1
        $x_1_9 = "Credential" ascii //weight: 1
        $x_1_10 = "procName" ascii //weight: 1
        $x_1_11 = "fileName" ascii //weight: 1
        $x_1_12 = "AddressOfEntryPoint" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Redline_GF_2147779920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GF!MTB"
        threat_id = "2147779920"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 [0-20] 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 [0-20] 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 [0-20] 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 [0-20] 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 [0-20] 33 00 31 00 39 00 5c 00 41 00 64 00 64 00 49 00 6e 00 [0-20] 72 00 6f 00 63 00 65 00 73 00 73 00 33 00 32 00 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_5_2 = ".NPROTECTET" ascii //weight: 5
        $x_5_3 = "FromBase64String" ascii //weight: 5
        $x_1_4 = "e_magic" ascii //weight: 1
        $x_1_5 = "e_lfanew" ascii //weight: 1
        $x_1_6 = "hProcess" ascii //weight: 1
        $x_1_7 = "VirtualAddress" ascii //weight: 1
        $x_1_8 = "procName" ascii //weight: 1
        $x_1_9 = "fileName" ascii //weight: 1
        $x_1_10 = "AddressOfEntryPoint" ascii //weight: 1
        $x_1_11 = "Expect100Continue" ascii //weight: 1
        $x_1_12 = "DownloadString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Redline_GH_2147780309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GH!MTB"
        threat_id = "2147780309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 02 11 03 11 01 11 03 11 01 8e 69 5d 91 02 11 03 91 61 d2 9c 20 ?? ?? ?? ?? 7e}  //weight: 10, accuracy: Low
        $x_1_2 = "Afmguwfzhihzppwws" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GH_2147780309_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GH!MTB"
        threat_id = "2147780309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "@C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AddInProcess32.exe" wide //weight: 10
        $x_5_2 = "Expect100Continue" ascii //weight: 5
        $x_5_3 = "FromBase64String" ascii //weight: 5
        $x_1_4 = "e_magic" ascii //weight: 1
        $x_1_5 = "e_lfanew" ascii //weight: 1
        $x_1_6 = "hProcess" ascii //weight: 1
        $x_1_7 = "VirtualAddress" ascii //weight: 1
        $x_1_8 = "procName" ascii //weight: 1
        $x_1_9 = "fileName" ascii //weight: 1
        $x_1_10 = "AddressOfEntryPoint" ascii //weight: 1
        $x_1_11 = "X509Certificate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Redline_NEA_2147824719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEA!MTB"
        threat_id = "2147824719"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 2d 08 08 6f 42 00 00 0a 13 04 de 33 07 2b cc 73 47 00 00 0a 2b c8 73 48 00 00 0a 2b c3 0d 2b c2 08 2c 07 08 6f 43 00 00 0a 00 dc}  //weight: 1, accuracy: High
        $x_1_2 = "Lhewzgvbldcvpgair" wide //weight: 1
        $x_1_3 = "Renevct_Zdrpkpqz.bmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEB_2147824720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEB!MTB"
        threat_id = "2147824720"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QBlkr6u1C2EuRnPIx3YNNhDbeSqwLZ09eXarA2aJhqZO0tXI1TdxFoJnOqcEb9MgCkKSKzD4uds=" wide //weight: 1
        $x_1_2 = "joSIahmaem" wide //weight: 1
        $x_1_3 = "C:\\Tefsdddddmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEC_2147825083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEC!MTB"
        threat_id = "2147825083"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {12 00 12 03 12 04 08 12 05 12 06 12 07 12 08 02 7e 07 00 00 04 06 97 29 1c 00 00 11 13 09 00 de 1f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NED_2147825084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NED!MTB"
        threat_id = "2147825084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0c 07 6f 24 00 00 0a 0d 09 69 13 04 11 04 8d 11 00 00 01 0a 38 18 00 00 00 07 06 08 11 04 6f 42 00 00 0a 13 05 08 11 05 58 0c 11 04 11 05 59 13 04 11 04 16}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEF_2147825936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEF!MTB"
        threat_id = "2147825936"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 72 59 00 00 70 72 ?? 00 00 70 28 ?? 00 00 0a 26 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "mshta" wide //weight: 1
        $x_1_3 = "Encoding.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_MA_2147827121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.MA!MTB"
        threat_id = "2147827121"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {07 18 58 0b 07 02 6f 1f 00 00 0a 3f 93 ff ff ff 06 6f 20 00 00 0a 28 01 00 00 2b}  //weight: 10, accuracy: High
        $x_5_2 = {57 15 02 08 09 08 00 00 00 10 00 00 00 00 00 00 01 00 00 00 20 00 00 00 05 00 00 00 01 00 00 00 0b 00 00 00 03 00 00 00 23 00 00 00 0e 00 00 00 03 00 00 00 02}  //weight: 5, accuracy: High
        $x_2_3 = "TryDequeue" ascii //weight: 2
        $x_2_4 = "Enqueue" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_MA_2147827121_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.MA!MTB"
        threat_id = "2147827121"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 1a 11 19 16 11 19 8e 69 6f 51 00 00 0a 13 1b 06 11 1b 16 11 1b 8e 69 6f 89 00 00 0a de 5b}  //weight: 2, accuracy: High
        $x_2_2 = {33 37 63 62 36 34 38 61 2d 37 66 64 31 2d 34 35 61 36 2d 39 35 32 35 2d 36 66 64 32 33 62 33 63 34 65 66 39 7d 00 7b 37 35 33 62 32 31 61 31 2d 39 35 33 62 2d 34 35 38 61 2d 38 65 36 35 2d 36 65 34 34 63 39 35 30 31 33 36 66 7d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_MA_2147827121_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.MA!MTB"
        threat_id = "2147827121"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 05 11 05 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 00 11 05 1b 8d 05 00 00 01 13 08 11 08 16 72 ?? ?? ?? 70 a2 11 08 17 11 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "DisableAntiSpyware" wide //weight: 1
        $x_1_3 = "TamperProtection" wide //weight: 1
        $x_1_4 = "RegistryEdit" ascii //weight: 1
        $x_1_5 = "DisableBehaviorMonitoring" wide //weight: 1
        $x_1_6 = "DisableRealtimeMonitoring" wide //weight: 1
        $x_1_7 = "/c schtasks /create /f /sc MINUTE /MO 5 /rl highest /tn" wide //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
        $x_1_9 = "UserAccountControl.exe" wide //weight: 1
        $x_1_10 = "CheckDefender" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_B_2147827159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.B!MTB"
        threat_id = "2147827159"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 06 1f 3c 58 16 52 06 1f 1c 58}  //weight: 1, accuracy: High
        $x_1_2 = "fsdhjiufsd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEH_2147827662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEH!MTB"
        threat_id = "2147827662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 28 43 00 00 0a 25 26 0b 28 ?? 00 00 0a 25 26 07 16 07 8e 69 6f ?? 00 00 0a 25 26 0a 28 35 00 00 0a 25 26 06 6f 39 00 00 0a 25 26 0c}  //weight: 1, accuracy: Low
        $x_1_2 = "d2luZG93cy5kZWNvZGVyLm1hbmFnZXIuc29mdHdhcmUl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEI_2147827664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEI!MTB"
        threat_id = "2147827664"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e 2a 01 00 04 0e 06 17 59 e0 95 58 0e 05 28 46 05 00 06 58 54 2a}  //weight: 1, accuracy: High
        $x_1_2 = "TReplaceokReplaceenReplaces.tReplacex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_UW_2147828108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.UW!MTB"
        threat_id = "2147828108"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 05 19 8d ?? ?? ?? 01 13 13 11 13 16 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a a2 11 13 17 7e ?? ?? ?? 0a a2 11 13 18 09 11 05 6f ?? ?? ?? 0a a2 11 13 13 06 72 ?? ?? ?? 70 28 ?? ?? ?? 06 28 ?? ?? ?? 06 13 07 28 ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a 13 08 72 ?? ?? ?? 70 13 09 11 09}  //weight: 10, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "ToCharArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEE_2147828111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEE!MTB"
        threat_id = "2147828111"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 07 6f 25 00 00 0a 03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 0c 06 72 ?? ?? ?? 70 08 28 3a 01 00 0a 6f 3b 01 00 0a 26 07 17 58 0b 07 02 6f ?? ?? ?? 0a 32 ca}  //weight: 1, accuracy: Low
        $x_1_2 = "Chilblain" wide //weight: 1
        $x_1_3 = "Gasdl94jlajsdetDevasdl94jlajsdiceCapasdl94jlajsds" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NZ_2147828297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NZ!MTB"
        threat_id = "2147828297"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 08 09 08 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 02 7b ?? ?? ?? 04 09 91 61 d2 9c 00 09 17 58 0d 09 02 7b ?? ?? ?? 04 8e 69 fe 04 13 04 11 04 2d c9}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ABG_2147828598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ABG!MTB"
        threat_id = "2147828598"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 ff a2 3f 09 1e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 c5 00 00 00 89 00 00 00 45 01 00 00 8e 04 00 00 ae 02}  //weight: 5, accuracy: High
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "get_IsAttached" ascii //weight: 1
        $x_1_4 = "DownloadAndExecuteUpdate" ascii //weight: 1
        $x_1_5 = "FullInfoSender" ascii //weight: 1
        $x_1_6 = "GameLauncher" ascii //weight: 1
        $x_1_7 = "GetAllNetworkInterfaces" ascii //weight: 1
        $x_1_8 = "GetBrowsers" ascii //weight: 1
        $x_1_9 = "GetDefaultIPv4Address" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_QP_2147828800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.QP!MTB"
        threat_id = "2147828800"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {04 fe 0c 02 00 91 61 d2 9c 00 fe 0c 02 00 20 ?? ?? ?? 00 58 fe 0e 02 00 fe 0c 02 00 7e ?? ?? ?? 04 8e 69 fe 04 fe 0e 03 00 fe 0c 03 00}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_QS_2147828912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.QS!MTB"
        threat_id = "2147828912"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 02 11 03 11 01 11 03 11 01 8e 69 5d 91 11 04 11 03 91 61 d2 9c 20}  //weight: 10, accuracy: High
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "DynamicInvoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_RA_2147829159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.RA!MTB"
        threat_id = "2147829159"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "M03illa" ascii //weight: 1
        $x_1_2 = "RosComNadzor" ascii //weight: 1
        $x_1_3 = "NordApp" ascii //weight: 1
        $x_1_4 = "AllWallets" ascii //weight: 1
        $x_1_5 = "Discord" ascii //weight: 1
        $x_1_6 = "OpenVPN" ascii //weight: 1
        $x_1_7 = "GeckoRoamingName" ascii //weight: 1
        $x_1_8 = "ChromeGetRoamingName" ascii //weight: 1
        $x_1_9 = "BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_SC_2147829887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.SC!MTB"
        threat_id = "2147829887"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 00 16 11 00 8e 69 28 ?? ?? ?? 06 13 04 38 ?? ?? ?? ?? 73 ?? ?? ?? 0a 13 03 38 ?? ?? ?? ?? 11 04 03 28 ?? ?? ?? 06 28 ?? ?? ?? 06}  //weight: 10, accuracy: Low
        $x_1_2 = "T5AAZ" wide //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "Fabraka" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_SD_2147829888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.SD!MTB"
        threat_id = "2147829888"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 09 6f 39 00 00 0a 28 ?? ?? ?? 0a 13 04 11 04 28 ?? ?? ?? 0a 20 ?? ?? ?? ?? da 13 05 11 05 28 ?? ?? ?? 0a 28 ?? ?? ?? ?? 13 06 07 11 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 00 09 17 d6 0d 09 08 6f ?? ?? ?? 0a fe 04 13 07 11 07}  //weight: 10, accuracy: Low
        $x_1_2 = "EZMOEpJDDf" ascii //weight: 1
        $x_1_3 = "get_Computer" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "WriteAllBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_D_2147829889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.D!MTB"
        threat_id = "2147829889"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {05 2c 0a 03 46 28 ?? ?? ?? 06 0a 2b 03 03 46 0a 04 2d 03 02 2b 1a 02 21 ?? ?? ?? ?? ?? ?? ?? ?? 5a 06 6a 61 03 17 58 04 17 59 05 28 ?? ?? ?? 06 2a}  //weight: 10, accuracy: Low
        $x_1_2 = {57 fd a2 35 09 00 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 39 00 00 00 27 00 00 00 4a 00 00 00 6b}  //weight: 1, accuracy: High
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GA_2147830212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GA!MTB"
        threat_id = "2147830212"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "37.139.129.142" ascii //weight: 1
        $x_1_2 = "PT1GbFBLMGR1UmN2bGVjWl" ascii //weight: 1
        $x_1_3 = "HR0cDovLzM3LjEzO" wide //weight: 1
        $x_1_4 = "DownloadFile" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_HA_2147830367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.HA!MTB"
        threat_id = "2147830367"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cutt.ly/CXAD5DL" ascii //weight: 1
        $x_1_2 = "ThreatDeal" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "Ahxtnrmgfnitfwtesbzrlaye" ascii //weight: 1
        $x_1_5 = "ICryptoTransform" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_IA_2147830369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.IA!MTB"
        threat_id = "2147830369"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 2d 2b 2e 2b 2f 2b 34 07 09 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 02 13 04 07 6f ?? ?? ?? 0a 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 de 24 08 2b d0 06 2b cf 6f ?? ?? ?? 0a 2b ca 0d 2b c9}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "DynamicInvoke" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_IB_2147830370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.IB!MTB"
        threat_id = "2147830370"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dLgCxreVdI" ascii //weight: 1
        $x_1_2 = "gu39jsYBtpDEGDdpaCO" ascii //weight: 1
        $x_1_3 = "Profile_encrypted_value%appdata%\\logins" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_IC_2147830371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.IC!MTB"
        threat_id = "2147830371"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 07 14 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? 0a 18 8d ?? ?? ?? ?? 14 14 14 17 7e ?? ?? ?? ?? 20 ?? ?? ?? ?? 97 29 ?? ?? ?? 11 26 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "sixB4l0" wide //weight: 1
        $x_1_3 = "sixB4l0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_IG_2147830420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.IG!MTB"
        threat_id = "2147830420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0c 16 13 04 2b 21 00 07 11 04 08 11 04 08 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 07 11 04 91 61 d2 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d d2}  //weight: 10, accuracy: Low
        $x_1_2 = "[KU][RWA]" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEK_2147830853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEK!MTB"
        threat_id = "2147830853"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 1e 00 00 0a 25 20 4c 04 00 00 20 ac 0d 00 00 6f 1f 00 00 0a 28 20 00 00 0a 72 59 00 00 70 28 0d 00 00 06 20 f4 01 00 00 20 ac 0d 00 00 6f 1f 00 00 0a 28 20 00 00 0a 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_VW_2147830943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.VW!MTB"
        threat_id = "2147830943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nominally.ru/exec/" ascii //weight: 1
        $x_1_2 = "uCenwzXchGqEhDLCqJfwmxGP" wide //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "Download" ascii //weight: 1
        $x_1_5 = "GhostlyCrypt.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_T_2147831120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.T!MTB"
        threat_id = "2147831120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 72 01 00 00 70 6f ?? ?? ?? 0a 0a de 0a 07 2c 06 07 6f ?? ?? ?? 0a dc 28 ?? ?? ?? 0a 72 8a 00 00 70 28 ?? ?? ?? 0a 06 28 ?? ?? ?? 0a}  //weight: 10, accuracy: Low
        $x_1_2 = "RegAsm.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_WX_2147831328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.WX!MTB"
        threat_id = "2147831328"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 06 8e 69 8d ?? ?? ?? ?? 0b 16 0c 38 ?? ?? ?? ?? 07 08 06 08 91 03 08 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d2 9c 08 17 58 0c 08 06 8e 69 32 e0}  //weight: 10, accuracy: Low
        $x_1_2 = "iJBVZDrTzuHwVzwpAAMfvobL" wide //weight: 1
        $x_1_3 = "81.161.229.110" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GLY_2147831509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GLY!MTB"
        threat_id = "2147831509"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 16 1f 3a 9d 6f ?? ?? ?? 0a 0c 08 16 9a 28 ?? ?? ?? 06 0d 06 09 6f ?? ?? ?? 0a 00 08 17 9a 28 ?? ?? ?? 06 0b 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 07 16 07 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 04 11 04 13 05 de 10}  //weight: 10, accuracy: Low
        $x_1_2 = "YFpoGQ@$VrUMf64tZ9eg^RiaQSZ^Pw%*" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "/C choice /C Y /N /D Y /T 5 & Del" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_UY_2147831764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.UY!MTB"
        threat_id = "2147831764"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "212.192.31.73" ascii //weight: 1
        $x_1_2 = "inconiiiococowg.ru" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "GVkOC04ODg0LWY0NzY1MDk5" wide //weight: 1
        $x_1_5 = "NDc0Ni05Y2M5LThhZjM2MTNjYTcxMX0sIEN1b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MSIL_Redline_GWX_2147831766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GWX!MTB"
        threat_id = "2147831766"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 06 11 06 08 6f ?? ?? ?? 0a 11 06 18 6f ?? ?? ?? 0a 11 06 18 6f ?? ?? ?? 0a 11 06 0d 2b 22 2b 23 2b 28 2b 2a 06 16 06 8e 69 6f ?? ?? ?? 0a 13 05 28 ?? ?? ?? 0a 11 05 6f ?? ?? ?? 0a 13 07 de 26 09 2b db 6f ?? ?? ?? 0a 2b d6 13 04 2b d4 11 04 2b d2}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GWV_2147832032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GWV!MTB"
        threat_id = "2147832032"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f ?? ?? ?? 0a 08 17 58 0c 08 02 8e 69 32 e4 07 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GWV_2147832032_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GWV!MTB"
        threat_id = "2147832032"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 06 58 0b 07 06 25 1f 3b 5c 1f 3b 5a 59 1f 38 58 08 07 58 46 61 52 06 17 58 0a 06 1f 13 37 e0}  //weight: 10, accuracy: High
        $x_1_2 = "Project35" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "SecureString<13,56,58,char>" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_R_2147832158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.R!MTB"
        threat_id = "2147832158"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO" ascii //weight: 1
        $x_1_2 = "ChromeGetRoamingName" ascii //weight: 1
        $x_1_3 = "ChromeGetName" ascii //weight: 1
        $x_1_4 = "RosComNadzor" ascii //weight: 1
        $x_1_5 = "sdf934asd" ascii //weight: 1
        $x_1_6 = "asdk9345asd" ascii //weight: 1
        $x_1_7 = "adkasd8u3hbasd" ascii //weight: 1
        $x_1_8 = "kkdhfakdasd" ascii //weight: 1
        $x_1_9 = "OpHandlerenVPHandlerN" wide //weight: 1
        $x_1_10 = "ProldCharotonVoldCharPN" wide //weight: 1
        $x_1_11 = "discord" wide //weight: 1
        $x_1_12 = "FileZilla" wide //weight: 1
        $x_1_13 = "NordVpn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GWF_2147832257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GWF!MTB"
        threat_id = "2147832257"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 28 1d 00 00 0a 0a 28 ?? ?? ?? 0a 04 6f ?? ?? ?? 0a 0b 28 ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 0b 06 07 28 ?? ?? ?? 06 0c 03 08 28 ?? ?? ?? 0a 00 03 03 7e 18 00 00 04 28}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "AES_Encrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GVX_2147832715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GVX!MTB"
        threat_id = "2147832715"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 06 58 0b 07 08 07 58 46 06 19 5d 17 58 61 52 06 17 58 0a 06 1f 12 32 e7 2a}  //weight: 10, accuracy: High
        $x_1_2 = "Project35" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GTV_2147833540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GTV!MTB"
        threat_id = "2147833540"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {13 0c 16 0c 08 12 0c 58 08 1f 3b 5e 1f 30 58 08 12 0c 58 46 61 52 08 17 58 0c 08 1f 11 37 e5}  //weight: 10, accuracy: High
        $x_10_2 = {11 08 12 12 58 11 08 1f 3b 5e 1f 39 58 11 08 12 12 58 46 61 52 11 08 17 58 13 08 11 08 1f 0f}  //weight: 10, accuracy: High
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "Project35.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Redline_GUC_2147833542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GUC!MTB"
        threat_id = "2147833542"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 11 04 16 11 04 8e 69 28 ?? ?? ?? 06 13 05 7e ?? ?? ?? ?? 07 11 04 16 11 05 28 ?? ?? ?? 06 00 00 11 05 16 fe 02 13 06 11 06 2d ce}  //weight: 10, accuracy: Low
        $x_1_2 = "Tnpmpjkunfyzfzbyp" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GJK_2147834119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GJK!MTB"
        threat_id = "2147834119"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {04 08 04 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 04 08 17 58 04 8e 69 5d 91 59 20 ?? ?? ?? ?? 58 17 58 20 ?? ?? ?? ?? 5d d2 9c 08 17 58 0c 08 6a 04 8e 69 17 59 6a 06 17 58 6e 5a 31 ac 0f 02 04 8e 69 17 59 28 ?? ?? ?? 2b 04}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEL_2147834120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEL!MTB"
        threat_id = "2147834120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 05 11 0a 8f 12 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEL_2147834120_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEL!MTB"
        threat_id = "2147834120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 b6 00 00 06 0b 07 1f 20 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 07 1f 10 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_5_2 = {06 28 81 00 00 0a 8e 69 17 fe 02 0b 28 ?? 00 00 06}  //weight: 5, accuracy: Low
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = "wifi.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEM_2147834121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEM!MTB"
        threat_id = "2147834121"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 16 0b 2b 2d 02 07 6f ?? 00 00 0a 03 07 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 0c 06 72 ?? 0e 00 70 08 28 ?? 01 00 0a 6f ?? 01 00 0a 26 07 17 58 0b 07 02 6f ?? 00 00 0a 32 ca}  //weight: 10, accuracy: Low
        $x_5_2 = "NordVpn.exe*MyGToMyGkens.tMyGxt" wide //weight: 5
        $x_5_3 = "cookies.sqlite" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAA_2147834126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAA!MTB"
        threat_id = "2147834126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "H4sIAAAAAAAEAMstTs4vyslMAgAUtzbxCAAAAA==" wide //weight: 5
        $x_5_2 = "H4sIAAAAAAAEAAuuLC5JzdULKs0rycxN1fPMK0ktyi8ITi0qy0xOLQYAcrSvBh4AAAA=" wide //weight: 5
        $x_5_3 = "H4sIAAAAAAAEAHNOzMnJzEt3zs8rS80ryczPAwAbw5LpEQAAAA==" wide //weight: 5
        $x_1_4 = "System.Reflection.Emit.EnumBuilder" ascii //weight: 1
        $x_1_5 = "UnityEngine.Vector2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GJS_2147834239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GJS!MTB"
        threat_id = "2147834239"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 03 08 17 58 03 8e 69 5d 91 59 20 ?? ?? ?? ?? 58 17 58 20 ?? ?? ?? ?? 5d d2 9c 08 17 58 0c 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a 31 ac 0f 01 03 8e 69 17 59 28 ?? ?? ?? 2b 03 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "ffchkffaffsdssfj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GJP_2147834303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GJP!MTB"
        threat_id = "2147834303"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {16 10 01 02 1f 64 31 06 03 16 fe 01 2b 01 16 0c 08 2c 0a 72 25 0e 00 70 0b 17 10 01 00 00 03 0d 09 2c 04 07 0a 2b 04 14 0a 2b 00 06 2a}  //weight: 10, accuracy: High
        $x_1_2 = "pastebin.pl/view/raw/231376ec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAB_2147834395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAB!MTB"
        threat_id = "2147834395"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 0b 2b 2d 02 07 6f 27 00 00 0a 03 07 03 6f 4d 00 00 0a 5d 6f 27 00 00 0a 61 0c 06 72 ?? ?? 00 70 08 28 3a 01 00 0a 6f 3b 01 00 0a 26 07 17 58 0b 07 02}  //weight: 10, accuracy: Low
        $x_5_2 = {0a de 19 02 28 84 00 00 06 03 28 83 00 00 06 28 84 00 00 06 0a de 05}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GKU_2147835282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GKU!MTB"
        threat_id = "2147835282"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 08 03 8e 69 5d 7e ?? ?? ?? ?? 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 03 08 17 58 03 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 1b 2d 36 26 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a 31 b1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GKU_2147835282_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GKU!MTB"
        threat_id = "2147835282"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {91 03 06 03 8e b7 8c ?? ?? ?? ?? 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 91 61 02 06 17 28 ?? ?? ?? 0a 18 28 ?? ?? ?? 0a 8c ?? ?? ?? ?? 28 ?? ?? ?? 0a 02 8e b7 8c ?? ?? ?? ?? 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 91 59 20 ?? ?? ?? ?? 28 ?? ?? ?? 0a 18 28 ?? ?? ?? 0a 58 20 ?? ?? ?? ?? 28 ?? ?? ?? 0a 18 28 ?? ?? ?? 0a 5d d2 9c 00 06 11 04 12 00}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_RE_2147835538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.RE!MTB"
        threat_id = "2147835538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OpenVPN" ascii //weight: 1
        $x_1_2 = "BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO" ascii //weight: 1
        $x_1_3 = "ChromeGetRoamingName" ascii //weight: 1
        $x_2_4 = "sdf934asd" ascii //weight: 2
        $x_2_5 = "asdk9345asd" ascii //weight: 2
        $x_2_6 = "adkasd8u3hbasd" ascii //weight: 2
        $x_2_7 = "kkdhfakdasd" ascii //weight: 2
        $x_3_8 = {5d 6f 37 00 00 0a 61 0c 06 72 63 08 00 70 08 28 a4 00 00 0a 6f a5 00 00 0a}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAD_2147835614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAD!MTB"
        threat_id = "2147835614"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 04 11 04 7e ?? 00 00 04 11 07 09 08 28 ?? 00 00 06 17 73 ?? 00 00 0a 13 05 7e ?? 00 00 04 11 05 11 06 16 11 06 8e 69 28 ?? 00 00 06 7e ?? 00 00 04 11 05 28 ?? 00 00 06 7e ?? 00 00 04 28 ?? 00 00 06 13 08 7e ?? 00 00 04 11 08}  //weight: 10, accuracy: Low
        $x_5_2 = "RHluYW1pY0RsbEludm9rZVR5cGU=" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GKV_2147835706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GKV!MTB"
        threat_id = "2147835706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 7b 02 00 00 04 04 02 7b 02 00 00 04 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 03 61 d2 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAE_2147835728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAE!MTB"
        threat_id = "2147835728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0a 03 07 03 6f 5d 00 00 0a 5d 6f 37 00 00 0a 61 0c 06 72 63 08 00 70 08 28 a4 00 00 0a 6f a5 00 00 0a 26 00 07 17 58 0b 07 02 6f 5d 00 00 0a fe 04 0d 09 2d c4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GAT_2147835858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GAT!MTB"
        threat_id = "2147835858"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 04 11 04 d2 13 06 12 06 72 ?? ?? ?? ?? 28 ?? ?? ?? 0a 13 05 06 11 04 11 05 a2 07 11 05 11 04 d2 6f ?? ?? ?? 0a 07 11 05 6f ?? ?? ?? 0a 11 04 d2 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 2d bc}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AGCQ_2147835869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AGCQ!MTB"
        threat_id = "2147835869"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 01 11 03 11 02 11 03 8e 69 5d 91 7e ?? ?? ?? 04 11 02 91 61 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GTC_2147836084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GTC!MTB"
        threat_id = "2147836084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 17 58 0a 06 1f 0f 34 12 02 06 58 03 06 58 46 06 1f 3b 5e 1f 37 58 61 52 2b e5}  //weight: 10, accuracy: High
        $x_10_2 = {11 06 12 1a 58 11 06 25 1f 3b 5c 1f 3b 5a 59 1f 32 58 11 06 12 1a 58 46 61 52 11 06 17 58 13 06 11 06 1f 12 37 da}  //weight: 10, accuracy: High
        $x_1_3 = "Project35.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Redline_GTD_2147836086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GTD!MTB"
        threat_id = "2147836086"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 1a 58 11 04 16 08 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 7e ?? ?? ?? ?? 11 05 6f ?? ?? ?? 0a 7e ?? ?? ?? ?? 02 6f ?? ?? ?? 0a 7e ?? ?? ?? ?? 6f ?? ?? ?? 0a 17 59 28 ?? ?? ?? 0a 16 7e ?? ?? ?? ?? 02 1a 28 ?? ?? ?? 0a 11 05 0d}  //weight: 10, accuracy: Low
        $x_1_2 = "IosDoxedmfjritFasm" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAG_2147836093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAG!MTB"
        threat_id = "2147836093"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 1e 58 11 05 1f 5d 6f 74 00 00 0a 54 11 05 17 06 1e 58 4a 17 59 6f 75 00 00 0a 25 1f 7a 6f 74 00 00 0a 16 fe 04 16 fe 01 13 06 1f 74 6f 74 00 00 0a 16 fe 04 16 fe 01 13 07 11 05 06 1e 58 4a 17 58 6f 44 00 00 0a 13 05}  //weight: 10, accuracy: High
        $x_2_2 = "SmartAssembly.HouseOfCards" ascii //weight: 2
        $x_2_3 = "aspnet_wp.exe" wide //weight: 2
        $x_2_4 = "w3wp.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAI_2147836096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAI!MTB"
        threat_id = "2147836096"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 8e 69 1b 59 8d 77 00 00 01 0a 02 1b 06 16 02 8e 69 1b 59 28 2f 01 00 0a 06 16 14 28 bf 00 00 06 0b 25 03 6f da 00 00 0a 07 28 9b 00 00 06 6f 6a 00 00 0a 2a}  //weight: 10, accuracy: High
        $x_2_2 = "ExpandEnvironmentVariables" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AGAF_2147836102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AGAF!MTB"
        threat_id = "2147836102"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 09 11 04 8e 69 1f 40 12 05 28 ?? ?? ?? 06 26 11 04 16 09 11 04 8e 69 28 ?? ?? ?? 0a 00 09 11 04 8e 69 11 05 12 06 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GTM_2147836137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GTM!MTB"
        threat_id = "2147836137"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 06 1a 58 4a 03 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? ?? ?? 06 03 06 1a 58 4a 17 58 03 8e 69 5d 91 59}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GTN_2147836187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GTN!MTB"
        threat_id = "2147836187"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 08 03 8e 69 5d 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 0a 03 08 17 58 03 8e 69 5d 91 59 ?? ?? ?? ?? ?? 58 17 58}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GAB_2147836318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GAB!MTB"
        threat_id = "2147836318"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 07 1d 2d 49 26 26 26 7e ?? ?? ?? ?? 06 18 28 ?? ?? ?? 06 7e ?? ?? ?? ?? 06 28 ?? ?? ?? ?? 0d 7e ?? ?? ?? ?? 09 02 16 02 8e 69 28 ?? ?? ?? 06 2a 0a 38 ?? ?? ?? ?? 0b 38 ?? ?? ?? ?? 0c 2b 92 28 ?? ?? ?? 06 2b 9f}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GAF_2147836434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GAF!MTB"
        threat_id = "2147836434"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {04 08 04 8e 69 5d 7e ?? ?? ?? ?? 04 08 04 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 04 08 17 58 04 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 1b 2d 36 26 08 6a 04 8e 69 17 59 6a 06 17 58 6e 5a 31 b1}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_RS_2147836443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.RS!MTB"
        threat_id = "2147836443"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 18 5b 8d 0d 00 00 01 2b 1e 16 0c 2b 1d 07 08 18 5b 02 08 18 6f 14 00 00 0a 1f 10 28 15 00 00 0a 9c 08 18 58 0c 2b 03 0b 2b df 08 06 32 02 2b 05 2b db 0a 2b ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GAC_2147836516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GAC!MTB"
        threat_id = "2147836516"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CYPXcX5OVbWEba7T3HR" ascii //weight: 1
        $x_1_2 = "AOXgvb5ukYHMMGHHXXt" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GBH_2147836728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GBH!MTB"
        threat_id = "2147836728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 08 03 8e 69 5d 7e ?? ?? ?? ?? 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 03 08 17 58 03 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 1d 2c 08 15 2d 41 26 15 2c f3}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GBK_2147836955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GBK!MTB"
        threat_id = "2147836955"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dbq@roobkqMol`bpp" ascii //weight: 1
        $x_1_2 = "QKXTKRpolJRR" ascii //weight: 1
        $x_1_3 = "7IRTUALxLLOC$X.U" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "hyrateDyer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_MG_2147837006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.MG!MTB"
        threat_id = "2147837006"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 09 16 13 0a 2b 22 11 09 11 0a 9a 13 0b 00 06 11 0b 6f ?? ?? ?? 06 13 0c 11 0c 2c 05 00 17 0d 2b 0f 00 11 0a 17 58 13 0a 11 0a 11 09 8e 69 32 d6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_MG_2147837006_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.MG!MTB"
        threat_id = "2147837006"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 7e 29 00 00 04 06 91 20 34 03 00 00 59 d2 9c 00 06 17 58 0a 06 7e 29 00 00 04 8e 69 fe 04 0b 07 2d d7}  //weight: 5, accuracy: High
        $x_1_2 = "IJOAFIFH" ascii //weight: 1
        $x_1_3 = "IJUADFWF" ascii //weight: 1
        $x_1_4 = "baza.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAJ_2147837073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAJ!MTB"
        threat_id = "2147837073"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2d 08 08 16 1a 28 25 00 00 0a 08 16 28 26 00 00 0a 13 04 11 04 8d 11 00 00 01 25 17 73 27 00 00 0a 13 05 06 6f 1f 00 00 0a 1b 6a 59 1a 6a 59 13 06 07 06 11 05 11 06 11 04 6a}  //weight: 5, accuracy: High
        $x_5_2 = {13 04 11 04 8e 2c 05 11 04 16 02 a2 14 11 04 6f 15 00 00 0a 13 05 11 05}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GBN_2147837154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GBN!MTB"
        threat_id = "2147837154"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 09 02 09 91 07 09 04 5d 93 28 ?? ?? ?? 06 d2 9c 00 09 17 58 0d 09 06 fe 04 13 04 11 04 2d df}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GBP_2147837200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GBP!MTB"
        threat_id = "2147837200"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 0e 11 12 58 11 15 11 15 8e 69 12 02 17 19 6f ?? ?? ?? 06 26 11 0f 1f 28 58 13 0f 11 11 17 58 13 11 11 11 11 10 17 59 3e 70 ff ff ff}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAK_2147837662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAK!MTB"
        threat_id = "2147837662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "I_LOVE_HENTAI" ascii //weight: 5
        $x_5_2 = "$$@$A$$@$s$$@$s$$@$e$$@$m$$@$b$$@$l$$@$y$$@$" wide //weight: 5
        $x_5_3 = "$$@$L$$@$o$$@$a$$@$d$$@$" wide //weight: 5
        $x_5_4 = "$$@$E$$@$n$$@$t$$@$r$$@$y$$@$P$$@$o$$@$i$$@$n$$@$t$$" wide //weight: 5
        $x_5_5 = "$$@$I$$@$n$$@$v$$@$o$$@$k$$@$e$$@$" wide //weight: 5
        $x_1_6 = "https://hastebin.com/raw/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAM_2147837832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAM!MTB"
        threat_id = "2147837832"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "1abd2938-b5ab-4607-97ae-8308b26ac7f6" ascii //weight: 5
        $x_2_2 = "Windows Biometrics Client API" ascii //weight: 2
        $x_2_3 = "0.9.8.6371" ascii //weight: 2
        $x_2_4 = "ZametkeR.Configurations" ascii //weight: 2
        $x_2_5 = "VwKLGpT.Consumers" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ABGQ_2147837955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ABGQ!MTB"
        threat_id = "2147837955"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 1d 12 03 2b 1c 2b 21 07 02 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a de 20 08 2b e0 28 ?? ?? ?? 0a 2b dd 06 2b dc}  //weight: 2, accuracy: Low
        $x_1_2 = "Npnzijuspvhgfqqgj.Fgfvmyfqisiziu" wide //weight: 1
        $x_1_3 = "Uehbsuajyfbdtc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GBU_2147838027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GBU!MTB"
        threat_id = "2147838027"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 63 11 62 6c 11 63 6c 28 ?? ?? ?? 0a 26 28 ?? ?? ?? 0a 26 28 ?? ?? ?? 0a 26 72 01 00 00 70 28 ?? ?? ?? 0a 26 11 07 07 03 07 91 09 61 d2 9c 1f 0a 13 64 1f 10 13 65 28 ?? ?? ?? 0a 26}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GCE_2147838070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GCE!MTB"
        threat_id = "2147838070"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 00 06 18 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 0b 02 28 ?? ?? ?? 0a 0c 07 08 16 08 8e 69 6f ?? ?? ?? 0a 0d 09 13 04 de 0b}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "JnPEHz/aCRFys+taF4Xf1Q==" wide //weight: 1
        $x_1_4 = "14+JhTXUrLhZBw5F+2kvUQ==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAO_2147838273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAO!MTB"
        threat_id = "2147838273"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 2b 00 00 0a 28 2c 00 00 0a 72 2d 00 00 70 28 2d 00 00 0a 28 22 00 00 06 28 2e 00 00 0a 15 16 28 2f 00 00 0a 80 0a 00 00 04 7e 0a 00 00 04 17 9a 28 2e 00 00 0a 28 2d 00 00 0a 28 22 00 00 06 28 2e 00 00 0a 28 2d 00 00 0a 80 0b 00 00 04 2a}  //weight: 10, accuracy: High
        $x_2_2 = "CpyoManCAyTC" ascii //weight: 2
        $x_2_3 = "JAvAywonobRfDApysw" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GCT_2147838514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GCT!MTB"
        threat_id = "2147838514"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UFNOTUJtWFpRTCU=" wide //weight: 1
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "PSNMBmXZQL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAP_2147838571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAP!MTB"
        threat_id = "2147838571"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 7e 0a 00 00 04 17 9a 28 34 00 00 0a 28 35 00 00 0a 28 36 00 00 0a 28 1c 00 00 06 80 0b 00 00 04 7e 0f 00 00 04 7e 0a 00 00 04 18 9a 28 37 00 00 0a 28 34 00 00 0a 7e 0b 00 00 04 28 38 00 00 0a 00 14 d0 2f 00 00 01 28 28 00 00 0a 72 41 00 00 70 17 8d 17 00 00 01 25 16 7e 0f 00 00 04 7e 0a 00 00 04 18 9a 28 37 00 00 0a a2 14 14 14 17 28 39 00 00 0a 26 2a}  //weight: 10, accuracy: High
        $x_2_2 = "BFR.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAQ_2147838651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAQ!MTB"
        threat_id = "2147838651"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "clrjit.dll" wide //weight: 5
        $x_5_2 = "lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 5
        $x_4_3 = "myself.dll" ascii //weight: 4
        $x_3_4 = "UwVuqLlLJvprAoS3fc" ascii //weight: 3
        $x_3_5 = "dil2BPgckjnUlJwuku" ascii //weight: 3
        $x_3_6 = "bqOOkFIIPmT7b9OaZC" ascii //weight: 3
        $x_3_7 = "cEWlsYBUE0" ascii //weight: 3
        $x_2_8 = "ae9fe44e1323e91bcbd185ca1a14099fba7c021f" ascii //weight: 2
        $x_2_9 = "13.0.1.25517" ascii //weight: 2
        $x_1_10 = "get_Is64BitOperatingSystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GCV_2147838671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GCV!MTB"
        threat_id = "2147838671"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ALangzgenNVdCSPArmmFdg==" wide //weight: 1
        $x_1_2 = "C3554254475" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "TripleDESCryptoServiceProvider" ascii //weight: 1
        $x_1_6 = "DOSLauncher.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAR_2147838735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAR!MTB"
        threat_id = "2147838735"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "d1cc2bad-d6f7-47b8-afa8-3a9d4430dcc1" ascii //weight: 4
        $x_4_2 = "XONE.exe" ascii //weight: 4
        $x_4_3 = "YJ234j8hTZD59PoO" ascii //weight: 4
        $x_4_4 = "HTzuzASbJnmrlEgdRfEQH" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GCU_2147838815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GCU!MTB"
        threat_id = "2147838815"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 63 11 62 6c 11 63 6c 28 ?? ?? ?? 0a 26 28 ?? ?? ?? 0a 26 28 ?? ?? ?? 0a 26 72 ?? ?? ?? ?? 28 ?? ?? ?? 0a 26 11 07 07 03 07 91 09 61 d2 9c}  //weight: 10, accuracy: Low
        $x_1_2 = "AraZZahAaaAuhaaZAA" ascii //weight: 1
        $x_1_3 = "AuaaahAhraaaZrAZr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Redline_NRZ_2147838857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NRZ!MTB"
        threat_id = "2147838857"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 6d 11 5d 34 0a 02 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 06 20 ?? ?? ?? cb 58 28 ?? ?? ?? 0a 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "Qo64Gj" ascii //weight: 1
        $x_1_3 = "delete from tbl_anggota" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_CO_2147838965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.CO!MTB"
        threat_id = "2147838965"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 05 1f 09 7e 6c 00 00 04 1f 29 7e 6c 00 00 04 1f 29 94 7e 6c 00 00 04 1f 0e 94 61 1f 41 5f 9e fe 02 13 06 11 06}  //weight: 5, accuracy: High
        $x_5_2 = {58 11 08 5d 93 61 d1 6f b5 00 00 0a 26 1f 10 13 0e}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GCX_2147838971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GCX!MTB"
        threat_id = "2147838971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 00 06 18 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 0b 02 28 ?? ?? ?? 06 0c 07 08 16 08 8e 69 6f ?? ?? ?? 0a 0d 09 13 04 2b 00 11 04 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "9JZwEemNfemAwoQDKTz0Fw==" wide //weight: 1
        $x_1_3 = "Concen7ra7e" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GCY_2147838972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GCY!MTB"
        threat_id = "2147838972"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hfsdkfdhgfshseffdfaffhfdch" ascii //weight: 1
        $x_1_2 = "ZkFwZG1wbXBkSWRBbQ==" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GDA_2147838973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GDA!MTB"
        threat_id = "2147838973"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 13 04 06 11 04 6f ?? ?? ?? 0a 13 05 11 05 16 fe 04 16 fe 01 13 08 11 08 2d 12 00 08 12 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0c 00 2b 20 00 07 11 05 58 03 58 07 5d 13 06 08 06 11 06 6f ?? ?? ?? 0a 8c ?? ?? ?? ?? 28 ?? ?? ?? 0a 0c 00 00 09 17 58 0d 09 02 6f ?? ?? ?? 0a fe 04 13 08 11 08 2d 98}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GDD_2147839030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GDD!MTB"
        threat_id = "2147839030"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0c 08 03 04 04 72 b6 22 00 70 6f ?? ?? ?? 0a 2d 03 18 2b 01 17 05 6f ?? ?? ?? 0a 13 04 2b 00 11 04}  //weight: 10, accuracy: Low
        $x_1_2 = "IgpVIBPv2" ascii //weight: 1
        $x_1_3 = "Cm9o83gm" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAS_2147839123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAS!MTB"
        threat_id = "2147839123"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6f 3b 00 00 0a 0e 06 71 3e 00 00 01 0e 09 71 3d 00 00 01 0e 06 71 3e 00 00 01 6f 3c 00 00 0a 1e 5b 6f 3a 00 00 0a 6f 3d 00 00 0a 0e 06 71 3e 00 00 01 17 6f 3e 00 00 0a 28 4e 00 00 06 0d 0e 0a 09 81 04 00 00 1b 0e 05 71 1a 00 00 01 0e 06 71 3e 00 00 01 6f 3f 00 00 0a 17 73 40 00 00 0a 13 04 0e 0b 11 04 81 38 00 00 01 02 1a 54 11 05 2a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GDE_2147839142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GDE!MTB"
        threat_id = "2147839142"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 11 07 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08}  //weight: 10, accuracy: Low
        $x_1_2 = "98a42a15-c16e-45ce-b4bc-c05d04e82f1f" ascii //weight: 1
        $x_1_3 = "get_IsHidden" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GDG_2147839144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GDG!MTB"
        threat_id = "2147839144"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0c 08 16 07 16 1f 10 28 ?? ?? ?? 0a 08 16 07 1f 0f 1f 10 28 ?? ?? ?? 0a 06 07 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0d 09 02 16 02 8e 69 6f ?? ?? ?? 0a 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "TransformFinalBlock" ascii //weight: 1
        $x_1_3 = "RijndaelManaged" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GDI_2147839216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GDI!MTB"
        threat_id = "2147839216"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hfsdkfdhgfshseffdfaffhfdch" ascii //weight: 1
        $x_1_2 = "fchfhfdgfadfdfrsfsshdkfffgh" ascii //weight: 1
        $x_1_3 = "hkgfsfdffdhfhddrfahhddsshcf" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GDK_2147839601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GDK!MTB"
        threat_id = "2147839601"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmVtb3ZlX09uUGx1Z2luVW5sb2FkaW5nd3JpdGVUb0NvbnNvbGU=" ascii //weight: 1
        $x_1_2 = "AnnaClarkNude334" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
        $x_1_4 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GDM_2147839603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GDM!MTB"
        threat_id = "2147839603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {26 2b 28 2b 29 2b 2e 2b 2f 2b 30 2b 35 0d 09 13 04 de 63 28 ?? ?? ?? 0a 2b e1 0b 2b e4 28 ?? ?? ?? 0a 2b c2 6f ?? ?? ?? 0a 2b d2 07 2b d5 28 ?? ?? ?? 0a 2b d0 0c 2b cf 08 2b ce 28 ?? ?? ?? 2b 2b c9}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GDS_2147839839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GDS!MTB"
        threat_id = "2147839839"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 11 0d 11 04 11 0d 17 59 99 02 7b 07 00 00 04 11 0d 99 06 5b 58 a1 00 11 0d 17 58 13 0d 11 0d 02 6f ?? ?? ?? 06 fe 04 13 0e 11 0e 2d d0}  //weight: 10, accuracy: Low
        $x_1_2 = "t0F4AanTouUCHU0IBecNq" ascii //weight: 1
        $x_1_3 = "vATVzdCddlXcgg/xl5nrlc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAT_2147839873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAT!MTB"
        threat_id = "2147839873"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 32 00 00 06 0a 28 18 00 00 06 0b 07 1f 20 8d 13 00 00 01 25 d0 31 00 00 04 28 0f 00 00 0a 6f 73 00 00 0a 07 1f 10 8d 13 00 00 01 25 d0 35 00 00 04 28 0f 00 00 0a 6f 74 00 00 0a 06 07 6f 75 00 00 0a 17 73 4e 00 00 0a 25 02 16 02 8e 69}  //weight: 10, accuracy: High
        $x_5_2 = "ScanProcesses.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_CR_2147840168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.CR!MTB"
        threat_id = "2147840168"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 72 05 00 00 70 73 ?? 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 16 0c 2b 21}  //weight: 5, accuracy: Low
        $x_1_2 = "appbundler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GCW_2147840215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GCW!MTB"
        threat_id = "2147840215"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2deoIkE3cIu" ascii //weight: 1
        $x_1_2 = "6THYK6rSn24R" ascii //weight: 1
        $x_1_3 = "qWMWMp5kk6N" ascii //weight: 1
        $x_1_4 = "95RPHVJaN3BdsOAQYYk10w==" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GEB_2147840315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GEB!MTB"
        threat_id = "2147840315"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 0f 18 9a 28 ?? ?? ?? 0a 16 8d ?? ?? ?? ?? 6f ?? ?? ?? 0a a2 14 14 16 17 28 ?? ?? ?? 0a 00 00 00 00 00 06 16 5a 0a 2b 00 00 00 06 16 fe 03 13 15 11 15 3a}  //weight: 10, accuracy: Low
        $x_1_2 = "i.ibb.co/DWY77J3/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GEF_2147840460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GEF!MTB"
        threat_id = "2147840460"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 00 44 00 2b 00 35 00 41 00 2b 00 39 00 7d 00 29 00 2b 00 7d 00 33 00 29 00 29 00 29 00 2b 00 7d 00 34 00 29 00 29 00 29}  //weight: 1, accuracy: High
        $x_1_2 = {00 36 00 2b 00 36 00 46 00 2b 00 31 00 39 00 29 00 29 00 2b 00 7d 00 41 00 29 00 2b 00 7d 00 32}  //weight: 1, accuracy: High
        $x_1_3 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAU_2147840468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAU!MTB"
        threat_id = "2147840468"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 06 03 11 06 91 07 11 06 07 8e 69 5d 91 61 08 61 d2 6f ?? 00 00 0a 00 00 11 06 17 58 13 06 11 06 03 8e 69 fe 04 13 07 11 07 2d d4}  //weight: 10, accuracy: Low
        $x_1_2 = "RPF:SmartAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GEG_2147840674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GEG!MTB"
        threat_id = "2147840674"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OqppWgiOwQV338GIb0" ascii //weight: 1
        $x_1_2 = "rwmjgBx63M" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
        $x_1_5 = "RijndaelManaged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GEH_2147840675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GEH!MTB"
        threat_id = "2147840675"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {04 06 18 28 ?? ?? ?? 06 16 2d f1 7e ?? ?? ?? ?? 06 28 ?? ?? ?? 06 0d 7e ?? ?? ?? ?? 09 03 16 03 8e 69 28 ?? ?? ?? 06 13 04 1e}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "RijndaelManaged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GEI_2147840751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GEI!MTB"
        threat_id = "2147840751"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 45 00 00 70 72 19 00 00 70 14 28 ?? ?? ?? 0a 18 8d 1c 00 00 01 25 16 d0 ?? ?? ?? ?? 28 ?? ?? ?? 0a a2 25 17 d0 ?? ?? ?? ?? 28 ?? ?? ?? 0a a2 28}  //weight: 10, accuracy: Low
        $x_1_2 = "GetMetxhod" ascii //weight: 1
        $x_1_3 = "Invxoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GEK_2147840753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GEK!MTB"
        threat_id = "2147840753"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 06 72 4a 03 00 70 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 0b 07 02 16 02 8e 69 6f ?? ?? ?? 0a 0c 2b 00 08 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "8fNkn/tVfEh+2GgzhmJp80CXCeiTOpfIaxtT388fpiA=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AR_2147840879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AR!MTB"
        threat_id = "2147840879"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 05 48 00 70 2b 04 2b 09 de 0d 28 ?? ?? ?? 06 2b f5 0a 2b f4 26 de e7 2b 01 2a 06 2b fc}  //weight: 2, accuracy: Low
        $x_1_2 = "updateadobe.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AR_2147840879_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AR!MTB"
        threat_id = "2147840879"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 01 28 27 00 00 0a 13 06 38 09 00 00 00 11 03 13 04 38 13 00 00 00 11 06 28 02 00 00 2b 28 03 00 00 2b 13 03}  //weight: 2, accuracy: High
        $x_1_2 = "virtkiosk.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AR_2147840879_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AR!MTB"
        threat_id = "2147840879"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 08 16 13 09 2b 43 11 08 11 09 9a 0d 00 09 6f ?? ?? ?? 0a 72 a3 00 00 70 6f ?? ?? ?? 0a 16 fe 01 13 0a 11 0a 2d 1c 00 12 02 08 8e 69 17 58 28 ?? ?? ?? 2b 00 08 08 8e 69 17 59 09 6f ?? ?? ?? 0a a2 00 00 11 09 17 58 13 09 11 09 11 08 8e 69 fe 04 13 0a 11 0a 2d af}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAV_2147840886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAV!MTB"
        threat_id = "2147840886"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 07 6f 27 00 00 0a 03 07 03 6f 4d 00 00 0a 5d 6f 27 00 00 0a 61 0c 06 72 41 09 00 70 08 28 3a 01 00 0a 6f 3b 01 00 0a 26 07 17 58 0b 07 02 6f 4d 00 00 0a 32 ca 06}  //weight: 10, accuracy: High
        $x_5_2 = "SELEMemoryCT * FMemoryROM WiMemoryn32_OperMemoryatingSMemoryystem" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GEJ_2147840977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GEJ!MTB"
        threat_id = "2147840977"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 07 1d 2d 49 26 26 26 7e ?? ?? ?? ?? 06 18 28 ?? ?? ?? 06 7e ?? ?? ?? ?? 06 28 ?? ?? ?? 06 0d 7e ?? ?? ?? ?? 09 03 16 03 8e 69 28 ?? ?? ?? 06 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "nhffskdsfkdfdhdafrffddhgfscffdf" ascii //weight: 1
        $x_1_3 = "RijndaelManaged" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_CIT_2147841051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.CIT!MTB"
        threat_id = "2147841051"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 0d 00 00 06 74 1e 00 00 01 72 12 01 00 70 20 00 01 00 00 14 14 14 6f 1c 00 00 0a}  //weight: 10, accuracy: High
        $x_10_2 = {28 19 00 00 06 28 1d 00 00 0a 72 2c 01 00 70 28 1a 00 00 06 13 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GEW_2147841489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GEW!MTB"
        threat_id = "2147841489"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 03 8e 69 5d 7e ?? ?? ?? ?? 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 03 08 19 58 18 59 03 8e 69 5d 91 59 20 03 01 00 00 58 18 59 17 59 20 ?? ?? ?? ?? 5d d2 9c 08 1e 2c b3 17 58 15 2d 36 26}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "hkgfsfdffdhfhddrfahghddsshcf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAW_2147841885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAW!MTB"
        threat_id = "2147841885"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 16 0b 2b 2d 02 07 6f ?? 00 00 0a 03 07 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 0c 06 72 ?? 09 00 70 08 28 ?? 01 00 0a 6f ?? 01 00 0a 26 07 17 58 0b 07 02}  //weight: 10, accuracy: Low
        $x_2_2 = "*wallet*" wide //weight: 2
        $x_2_3 = "moz_cookies" wide //weight: 2
        $x_2_4 = "Valve\\SteamLogin Data" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GFL_2147842023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GFL!MTB"
        threat_id = "2147842023"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 00 08 20 00 04 00 00 58 28 ?? ?? ?? 2b 07 02 08 20 00 04 00 00 6f ?? ?? ?? 0a 0d 08 09 58 0c 09 20 00 04 00 00 2f d8 0f 00 08}  //weight: 10, accuracy: Low
        $x_1_2 = "EwvvDihvQwEvLxyiMDrx" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GFM_2147842193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GFM!MTB"
        threat_id = "2147842193"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 8d 4f 00 00 01 13 04 7e 8f 01 00 04 02 1a 58 11 04 16 08 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 7e 7f 01 00 04 11 05}  //weight: 10, accuracy: Low
        $x_1_2 = "E5UuLlLvop" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEAX_2147842551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEAX!MTB"
        threat_id = "2147842551"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 28 15 00 00 0a 72 01 00 00 70 28 16 00 00 0a 2d 22 73 17 00 00 0a 0a 06 72 57 00 00 70 72 01 00 00 70 6f 18 00 00 0a de 0a 06 2c 06 06 6f 19 00 00 0a dc 72 01 00 00 70 28 1a 00 00 0a 26 16}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GFQ_2147842695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GFQ!MTB"
        threat_id = "2147842695"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "X6Cyq4ITuesFLso1rc" ascii //weight: 1
        $x_1_2 = "FromBase64CharArray" ascii //weight: 1
        $x_1_3 = "ADrIkpzMa4grD4RrUh" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "dXRYfwYG5" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GFP_2147842967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GFP!MTB"
        threat_id = "2147842967"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {58 00 0a 38 1a 00 00 00 02 06 02 06 91 03 06 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d2 9c 06 17 58 0a 06 02 8e 69 3f dd ff ff ff 02 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEBA_2147843079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEBA!MTB"
        threat_id = "2147843079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 2d 93 11 05 18 6f ?? 00 00 0a 1c 2c f2 11 05 18 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 06 11 06 07 16 07 8e 69 6f ?? 00 00 0a 13 07}  //weight: 10, accuracy: Low
        $x_1_2 = "SmartAssembly.HouseOfCards" ascii //weight: 1
        $x_1_3 = "GetPhysfaicafsfallyInstalledSystemMemory" ascii //weight: 1
        $x_1_4 = "DESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GFV_2147843110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GFV!MTB"
        threat_id = "2147843110"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {7e 02 00 00 04 72 59 00 00 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 0a 06 28 ?? ?? ?? 06 00 02 02 73 1c 00 00 06 7d 01 00 00 04 02 7b 01 00 00 04 6f}  //weight: 10, accuracy: Low
        $x_1_2 = "suiXDhDxUBI94W/XUkjk4n6YJe+n5GDb4DrZeuXPzUg=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEBD_2147844168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEBD!MTB"
        threat_id = "2147844168"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "bcd3cbeb-e649-485f-af1e-3d8788138df5" ascii //weight: 5
        $x_2_2 = "PIZZA.Resources" wide //weight: 2
        $x_2_3 = "IMPRIMIENDO TICKET" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GHK_2147844303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GHK!MTB"
        threat_id = "2147844303"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 08 03 8e 69 5d 7e ?? ?? ?? ?? 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 03 08 1e 58 1d 59 03 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 08 17 58 16 2c 3f 26 08 6a 03 8e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ARED_2147844798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ARED!MTB"
        threat_id = "2147844798"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 18 5b 8d 34 00 00 01 0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f 21 00 00 0a 1f 10 28 22 00 00 0a 9c 08 18 58 0c 08 06 32 e4}  //weight: 1, accuracy: High
        $x_1_2 = {06 0b 06 73 2e 00 00 0a 0c 08 07 6f ?? ?? ?? 0a 16 73 30 00 00 0a 0d 06 8e 69 8d 34 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 26 11 04 28 ?? ?? ?? 06 26 73 1f 00 00 06 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_PSKG_2147844904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.PSKG!MTB"
        threat_id = "2147844904"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {18 8d 03 00 00 01 25 16 28 ?? ?? ?? 0a a2 25 17 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 74 09 00 00 1b 18 28 50 00 00 06 74 09 00 00 1b 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 17 28 50 00 00 06 a2 0b de 0e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GHS_2147845584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GHS!MTB"
        threat_id = "2147845584"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 13 04 73 ?? ?? ?? 0a 13 05 11 05 11 04 6f ?? ?? ?? 0a 11 05 18 6f ?? ?? ?? 0a 11 05 18 6f ?? ?? ?? 0a 11 05 6f ?? ?? ?? 0a 13 06 11 06 07 16 07 8e 69 6f ?? ?? ?? 0a 13 07 28 ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a 13 08 11 08 6f ?? ?? ?? 0a 13 0a de 0d 13 09 11 09 6f 60 00 00 0a 13 0a de 00}  //weight: 10, accuracy: Low
        $x_1_2 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ABUP_2147846396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ABUP!MTB"
        threat_id = "2147846396"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 91 0b 7e ?? 00 00 04 06 7e ?? 00 00 04 06 7e ?? 00 00 04 5d 91 07 61 b4 9c 06 17 d6 0a 00 06 7e ?? 00 00 04 17 da fe 01 16 fe 01 13 06 11 06 2d 89}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_TL_2147846519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.TL!MTB"
        threat_id = "2147846519"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 12 00 00 0a 25 6f 13 00 00 0a 0b 06 20 94 3d 8d d7 28 01 00 00 06 0c 12 02 28 14 00 00 0a 74 01 00 00 1b 0d 20 89 c0 85 dd 2b 00 28 02 00 00 2b 09 6f 15 00 00 0a 09 16 09 8e 69 28 11 00 00 0a 12 02 28 16 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_PSNO_2147846655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.PSNO!MTB"
        threat_id = "2147846655"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 14 00 00 0a 58 0d 09 1a 32 ee 7e 15 00 00 0a 2d 08 08 16 1a 28 16 00 00 0a 08 16 28 17 00 00 0a 13 04 11 04 8d 1d 00 00 01 25 17 73 18 00 00 0a 13 05 06 6f 19 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GIF_2147846748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GIF!MTB"
        threat_id = "2147846748"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chuffed.exe" ascii //weight: 1
        $x_1_2 = "DjsVXCMYJFw5IHcWPCkIBy8UOUUNKzdfITNcUw==" ascii //weight: 1
        $x_1_3 = "ISgeADUjXFM=" ascii //weight: 1
        $x_1_4 = "encrypted_key" ascii //weight: 1
        $x_1_5 = "%DSK_23%cookies" ascii //weight: 1
        $x_1_6 = "settString.Replaceing[@name=\\UString.Replacesername\\]/vaString.Replaceluemoz_cookies" ascii //weight: 1
        $x_1_7 = "NordVpn.exe*NoGetDirectoriesrd" ascii //weight: 1
        $x_1_8 = "net.tcp://" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ABVR_2147847205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ABVR!MTB"
        threat_id = "2147847205"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 18 5b 8d ?? 00 00 01 0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 08 18 58 0c 08 06 32 e4}  //weight: 3, accuracy: Low
        $x_1_2 = "WindowsFormsApp98.Form1.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NEBE_2147847432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NEBE!MTB"
        threat_id = "2147847432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? 00 00 0a 11 04 13 05 11 05 17 58 13 04 11 04 07 8e 69 3f d8 ff ff ff 09 6f ?? 00 00 0a 13 06}  //weight: 10, accuracy: Low
        $x_1_2 = "WindowsFormsApp68" ascii //weight: 1
        $x_1_3 = "DynamicInvoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GJI_2147847440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GJI!MTB"
        threat_id = "2147847440"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hkgfffgsddfffdhdrfdafddsshcf" ascii //weight: 1
        $x_1_2 = "sddddfffhedfgddjfffffgjfsfkdgsacsafp" ascii //weight: 1
        $x_1_3 = "TripleDESCryptoServiceProvider" ascii //weight: 1
        $x_1_4 = "nhffskdgsfkdfffddadfrfffddhfscfdf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ARR_2147847655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ARR!MTB"
        threat_id = "2147847655"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {9a 0d 00 09 6f ?? ?? ?? 0a 72 61 00 00 70 6f ?? ?? ?? 0a 16 fe 01 13}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 1c 00 12 02 08 8e 69 17 58 28 ?? ?? ?? 2b 00 08 08 8e 69 17 59 09 6f ?? ?? ?? 0a a2 00 00 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_MBDG_2147847663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.MBDG!MTB"
        threat_id = "2147847663"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 00 40 00 40 00 40 00 50 00 30 00 33 00 40 00 50 00 45 00 32 00 40 00 50 00 30 00 33 00 40 00 50 00 45 00 32 00 40 00 50 00 30 00 33 00 40 00 50 00 45 00 32 00 40 00 50 00 31 00 33 00 40 00 40 00 40 00 50 00 45 00 36 00 40 00 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_CXIU_2147848894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.CXIU!MTB"
        threat_id = "2147848894"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TnVtMyA6IA==" ascii //weight: 1
        $x_1_2 = "$RXhjZXB0aW9uOiBJbnZhbGlkIGZvcm1hdA==" ascii //weight: 1
        $x_1_3 = "ZGFkYWg=" ascii //weight: 1
        $x_1_4 = "ZGRkZGRkZGRkZA==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GJZ_2147849421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GJZ!MTB"
        threat_id = "2147849421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 07 1d 2d 58 26 26 26 7e ?? ?? ?? ?? 06 18 28 ?? ?? ?? 06 7e ?? ?? ?? ?? 06 19 28 ?? ?? ?? 06 7e ?? ?? ?? ?? 06 28 ?? ?? ?? 06 0d 7e ?? ?? ?? ?? 09 03 16 03 8e 69}  //weight: 10, accuracy: Low
        $x_1_2 = "nhffskdgsfkdffddadfrffffdhffscfdf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AACT_2147849527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AACT!MTB"
        threat_id = "2147849527"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 25 08 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 06 6f ?? 00 00 0a 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0d 09 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "555555555555555555555d444444444444444444444A333333333333333333o222222222222222L1111111111111" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ARL_2147849682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ARL!MTB"
        threat_id = "2147849682"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 09 11 0a 9a 13 0b 00 06 11 0b 6f ?? ?? ?? 06 13 0c 11 0c 39 08 00 00 00 00 17 0d 38 12 00 00 00 00 11 0a 17 58 13 0a 11 0a 11 09}  //weight: 2, accuracy: Low
        $x_1_2 = "This assembly is protected by an unregistered version of Eziriz" wide //weight: 1
        $x_1_3 = "Nirtro CPU" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GKH_2147849692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GKH!MTB"
        threat_id = "2147849692"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 07 91 0d 06 07 06 08 91 9c 06 08 09 d2 9c 07 17 58 0b 08 17 59 0c 07 08 32 e5 06 2a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_PSRB_2147850089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.PSRB!MTB"
        threat_id = "2147850089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 1f 30 28 05 00 00 2b 28 ?? ?? ?? 2b 0b 73 7f 00 00 0a 28 ?? ?? ?? 0a 03 28 ?? ?? ?? 06 28 ?? ?? ?? 06 0c 08 73 81 00 00 0a 07 06 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 28 ?? ?? ?? 06 28 09 00 00 2b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AAFO_2147850727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AAFO!MTB"
        threat_id = "2147850727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 08 16 07 1f 0f 1f 10 1d 2d 61 26 26 26 26 26 26 7e ?? 00 00 04 06 07 1d 2d 58 26 26 26 7e ?? 00 00 04 06 18 28 ?? 00 00 06 7e ?? 00 00 04 06 19 28 ?? 00 00 06 7e ?? 00 00 04 06 28 ?? 00 00 06 0d 7e ?? 00 00 04 09 02 16 02 8e 69 28 ?? 00 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_PSSW_2147851384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.PSSW!MTB"
        threat_id = "2147851384"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 9b 00 00 0a 0a dd 20 00 00 00 26 72 03 00 00 70 72 a2 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 74 7e 00 00 01 0a dd 00 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_CXGG_2147851457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.CXGG!MTB"
        threat_id = "2147851457"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CYtzHLkrHAkRalizuL9TqbViN2pf3gZuqjcSFSH8/0w=" wide //weight: 1
        $x_1_2 = "5vf2aTkzVHwrOY8IRyuhrw==" wide //weight: 1
        $x_1_3 = "atOB2OJlnFEibHACE4N/7w==" wide //weight: 1
        $x_1_4 = "i98yOgarQK+TLXaZIFpcNg==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AAHI_2147851633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AAHI!MTB"
        threat_id = "2147851633"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 13 04 2b 1f 00 08 11 04 02 11 04 91 07 61 06 09 91 61 d2 9c 09 17 58 06 8e 69 5d 0d 00 11 04 17 58 13 04 11 04 02 8e 69 18 59 fe 04 13 05 11 05 2d d2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_PSTJ_2147851862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.PSTJ!MTB"
        threat_id = "2147851862"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 e1 01 00 06 06 20 e9 24 09 00 28 ce 01 00 06 26 dd 14 00 00 00 02 06 16 9a 79 5a 00 00 02 71 5a 00 00 02 81 5a 00 00 02 dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_CBYZ_2147851882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.CBYZ!MTB"
        threat_id = "2147851882"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_BrowserName" ascii //weight: 1
        $x_1_2 = "get_BrowserProfile" ascii //weight: 1
        $x_1_3 = "get_Logins" ascii //weight: 1
        $x_1_4 = "get_Autofills" ascii //weight: 1
        $x_1_5 = "get_Cookies" ascii //weight: 1
        $x_1_6 = "get_Location" ascii //weight: 1
        $x_1_7 = "get_Processes" ascii //weight: 1
        $x_1_8 = "get_SystemHardwares" ascii //weight: 1
        $x_1_9 = "get_FtpConnections" ascii //weight: 1
        $x_1_10 = "get_GameLauncherFiles" ascii //weight: 1
        $x_1_11 = "get_ScannedWallets" ascii //weight: 1
        $x_1_12 = "get_ScanTelegram" ascii //weight: 1
        $x_1_13 = "get_ScanVPN" ascii //weight: 1
        $x_1_14 = "get_ScanSteam" ascii //weight: 1
        $x_1_15 = "get_ScanDiscord" ascii //weight: 1
        $x_1_16 = "get_MachineName" ascii //weight: 1
        $x_1_17 = "get_OSVersion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AAJD_2147852487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AAJD!MTB"
        threat_id = "2147852487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 25 08 6f ?? 00 00 0a 25 17 28 ?? ?? 00 06 25 18 6f ?? 00 00 0a 25 06 6f ?? 00 00 0a 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0d}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_PSUQ_2147852852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.PSUQ!MTB"
        threat_id = "2147852852"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 47 00 00 0a 6f b9 01 00 0a 2c 20 72 93 2c 01 70 16 8d af 00 00 01 28 ba 01 00 0a 73 bb 01 00 0a 7a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AAIF_2147890311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AAIF!MTB"
        threat_id = "2147890311"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nvcie" wide //weight: 1
        $x_1_2 = {2e 00 72 00 00 05 65 00 73 00 00 05 6f 00 75 00 00 05 72 00 63 00}  //weight: 1, accuracy: High
        $x_1_3 = "33S33y33s3333t3e33m3" wide //weight: 1
        $x_1_4 = "R333e3333f3l33e3cti33o3n3" wide //weight: 1
        $x_1_5 = "33A333s333s3em33b3l33y33" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GMG_2147891574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GMG!MTB"
        threat_id = "2147891574"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 03 08 1b 58 1b 59 17 58 03 8e 69 5d 91 59 20 ?? ?? ?? ?? 58 1c 58 20 ?? ?? ?? ?? 5d d2 9c 08}  //weight: 10, accuracy: Low
        $x_1_2 = "aHR0cDpkb3RuZXRwZXJscy1jb20=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GNW_2147892459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GNW!MTB"
        threat_id = "2147892459"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IQJODDspIn8=" ascii //weight: 1
        $x_1_2 = "DBUUDC46IjciIzBRIg0XXjgTJFsqBgwP" ascii //weight: 1
        $x_1_3 = "u7xqmrM" ascii //weight: 1
        $x_1_4 = "ZPEKjB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_SK_2147892565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.SK!MTB"
        threat_id = "2147892565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows Perf Booster" ascii //weight: 1
        $x_1_2 = "Hydatids.exe" ascii //weight: 1
        $x_1_3 = "GearUp Corporation Copyright" ascii //weight: 1
        $x_1_4 = "Fps booster" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_RPX_2147893586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.RPX!MTB"
        threat_id = "2147893586"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 08 91 0d 08 1e 5d 13 04 03 11 04 9a 13 05 02 08 11 05 09 ?? ?? ?? ?? ?? 9c 08 17 d6 0c 08 07 31 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GND_2147894563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GND!MTB"
        threat_id = "2147894563"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "g0h4i5j8kElUmXo" ascii //weight: 1
        $x_1_2 = "qdrsstxu" ascii //weight: 1
        $x_1_3 = "CBHGIGONPNVU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_MBKS_2147894945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.MBKS!MTB"
        threat_id = "2147894945"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 08 02 8e 69 5d 7e ?? 00 00 04 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 06 02 08 20 8e 10 00 00 58 20 8d 10 00 00 59 02 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_PTAN_2147895027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.PTAN!MTB"
        threat_id = "2147895027"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 39 01 00 0a 17 73 27 01 00 0a 0c 08 02 16 02 8e 69 6f 3a 01 00 0a 08 6f 3b 01 00 0a 06 28 ?? 01 00 06 0d 28 ?? 01 00 06 09 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ARE_2147895198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ARE!MTB"
        threat_id = "2147895198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1e 2c f4 2b 37 00 2b 17 2b 18 2b 1d 9a 6f ?? ?? ?? 0a 14 14 6f ?? ?? ?? 0a 2c 02 de 24 de 10 06 2b e6 6f ?? ?? ?? 0a 2b e1 07 2b e0 26 de 00 1b 2c d3 16 2d c2 07 16 2d 02 17 58 0b 07 1f 0a 32 c4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ARE_2147895198_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ARE!MTB"
        threat_id = "2147895198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 09 2b 70 11 08 11 09 9a 0d 7e 2e 00 00 0a 13 04 09 6f 2f 00 00 0a 13 05 11 05 6f 30 00 00 0a 13 06 16 13 07 2b 38 11 04 11 06 11 07 8f 2d 00 00 01 28 31 00 00 0a 28 32 00 00 0a 13 04 11 07 11 06 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_PTBH_2147895668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.PTBH!MTB"
        threat_id = "2147895668"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 2a 00 00 0a 25 72 83 00 00 70 73 2b 00 00 0a 06 72 0a 01 00 70 28 ?? 00 00 0a 6f 2c 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ABNQ_2147896328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ABNQ!MTB"
        threat_id = "2147896328"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 01 00 00 70 28 ?? ?? ?? 06 0a 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GWD_2147896360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GWD!MTB"
        threat_id = "2147896360"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {04 13 04 28 ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 13 05 09 11 05 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 13 06 11 06 06 16 06 8e 69 6f ?? ?? ?? 0a 13 07 28 ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a 13 08 11 08 13 09 de 16}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "Dsxzas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GTT_2147896361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GTT!MTB"
        threat_id = "2147896361"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 24 11 47 5b 13 29 16 13 4c 2b 39 11 38 11 30 58 13 32 16 13 4d 2b 1e 11 45 11 44 61 13 1d 11 22 11 41 5a 13 37 11 30 6e 11 20 6a 61 6d 13 27 11 4d 17 58 13 4d 11 4d 20 ?? ?? ?? ?? 32 d9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GTT_2147896361_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GTT!MTB"
        threat_id = "2147896361"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 5b 00 00 70 0a 06 28 ?? ?? ?? 0a 0b 28 ?? ?? ?? 0a 07 16 07 8e 69 6f ?? ?? ?? 0a 0a 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0c 1f 61 6a 08}  //weight: 10, accuracy: Low
        $x_1_2 = "aW1wb3J0LmphdmEudXRpbC5yZWdleC5NYX" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ABHO_2147896500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ABHO!MTB"
        threat_id = "2147896500"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5b 6f 1f 00 00 0a 6f 22 00 00 0a fe 09 06 00 71 18 00 00 01 20 01 00 00 00 6f 23 00 00 0a 28 2d 00 00 06 fe 0e 03 00 fe 09 0a 00 fe 0c 03 00 81 04 00 00 1b fe 09 05 00 71 1b 00 00 01 fe 09 06 00 71 18 00 00 01 6f 24 00 00 0a 20 01 00 00 00 73 25 00 00 0a fe 0e 04 00 fe 09 0b 00 fe 0c 04 00 81 1d 00 00 01 fe 09 00 00 20 04 00 00 00 54 fe 0c 05 00 2a}  //weight: 2, accuracy: High
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ARD_2147896817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ARD!MTB"
        threat_id = "2147896817"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 14 00 00 06 0b 1b 8d d1 00 00 01 0c 16 0d 2b 0e 09 06 08 09 1b 09 59 6f 47 00 00 0a 58 0d 09 1b 32 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ARD_2147896817_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ARD!MTB"
        threat_id = "2147896817"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 00 11 02 91 11 00 11 03 91 58 20 00 01 00 00 5d 13 07 20 03 00 00 00 7e ?? 01 00 04 7b}  //weight: 1, accuracy: Low
        $x_1_2 = {11 00 11 02 11 00 11 03 91 9c 20 01 00 00 00 7e ?? 01 00 04 7b ?? 00 00 04 39}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ARD_2147896817_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ARD!MTB"
        threat_id = "2147896817"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SYrJaEpYcTUQiRDCTWAuhAib.dll" ascii //weight: 1
        $x_1_2 = "ZHKFTMlMZsCMnYSHOAFVTgnUZP.dll" ascii //weight: 1
        $x_1_3 = "fYoBTbolkDXtVpEuwPpsuvqbe.dll" ascii //weight: 1
        $x_1_4 = "NTZuQZzJoeRHJTu" ascii //weight: 1
        $x_1_5 = "Tesla Corporation Trademark" wide //weight: 1
        $x_1_6 = "a0f447ef-597a-4b70-887b-e80291fc3172" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AAXC_2147897143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AAXC!MTB"
        threat_id = "2147897143"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 04 07 28 ?? 19 00 06 11 04 17 28 ?? 19 00 06 11 04 08 28 ?? 19 00 06 11 04 6f ?? 00 00 0a 13 05 11 05 09 16 09 8e 69 28 ?? 19 00 06 0a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_PTCZ_2147897613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.PTCZ!MTB"
        threat_id = "2147897613"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 40 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 03 6f 42 00 00 0a 16 03 6f 43 00 00 0a 28 ?? 00 00 0a 6f 45 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_VQ_2147899450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.VQ!MTB"
        threat_id = "2147899450"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 08 11 09 9a 13 0a 00 06 11 0a 6f ?? ?? ?? ?? 13 0b 11 0b 39 08 00 00 00 00 17 0c 38 12 00 00 00 00 11 09 17 58 13 09 11 09 11 08 8e 69 3f cd ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NL_2147899701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NL!MTB"
        threat_id = "2147899701"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {73 29 00 00 0a 0a 06 20 e8 03 00 00 20 b8 0b 00 00 6f 2a 00 00 0a 28 2b 00 00 0a 00 72 b5 00 00 70 28 12 00 00 06 00 06 20 e8 03 00 00 20 b8 0b 00 00 6f 2a 00 00 0a 28 2b 00 00 0a 00 72 f7 00 00 70 28 12 00 00 06}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ASGC_2147899749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ASGC!MTB"
        threat_id = "2147899749"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 00 11 02 91 11 00 11 03 91 58 20 00 01 00 00 5d}  //weight: 1, accuracy: High
        $x_1_2 = {11 03 11 00 11 02 91 58 20 00 01 00 00 5d 13 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ASGD_2147899750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ASGD!MTB"
        threat_id = "2147899750"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 11 05 8f ?? 00 00 01 25 71 ?? 00 00 01 11 ?? 11 07 91 61 d2}  //weight: 2, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "WaitForSingleObject" ascii //weight: 1
        $x_1_4 = "CreateThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AMBA_2147900726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AMBA!MTB"
        threat_id = "2147900726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 02 11 04 73 ?? 00 00 0a 11 03 11 01 28 ?? 00 00 2b 28 ?? 00 00 2b 28}  //weight: 1, accuracy: Low
        $x_1_2 = "HMACSHA256" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "AesCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_BGAA_2147900989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.BGAA!MTB"
        threat_id = "2147900989"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 00 11 08 91 11 00 11 03 91 58 20 00 01 00 00 5d 13 07}  //weight: 2, accuracy: High
        $x_2_2 = {02 11 05 8f ?? 00 00 01 25 71 ?? 00 00 01 11 00 11 07 91 61 d2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GMY_2147901019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GMY!MTB"
        threat_id = "2147901019"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 16 0c 38 ?? ?? ?? ?? 06 08 08 28 ?? ?? ?? 0a 9c 07 08 03 08 03 8e 69 5d 91 9c 08 17 58 0c 08 20 00 01 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_PTCX_2147901144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.PTCX!MTB"
        threat_id = "2147901144"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 26 00 00 1b 08 28 ?? 00 00 0a 28 ?? 01 00 06 14 72 db 02 00 70 16 8d 04 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a a2 72 b9 06 00 70}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_LA_2147901472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.LA!MTB"
        threat_id = "2147901472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 06 8f 85 ?? ?? ?? 25 4b 03 06 95 61 54 06 17 59 0a 06 16}  //weight: 5, accuracy: Low
        $x_5_2 = {06 6e 17 07 1f 1f 5f 62 6a 5f 39 17 ?? ?? ?? 02 16 8f 85 ?? ?? ?? 25 4b ?? ?? ?? ?? ?? 1d 07 59 1f 1f 5f 64 61 54 07 17 59 0b 07 16}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GMX_2147901503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GMX!MTB"
        threat_id = "2147901503"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 07 11 04 11 02 11 04 91 02 11 04 02 28 ?? ?? ?? 06 5d 28 ?? ?? ?? 06 61 d2 9c 20 ?? ?? ?? ?? 38 ?? ?? ?? ?? 11 06 2a}  //weight: 10, accuracy: Low
        $x_10_2 = {11 03 11 04 11 02 11 04 91 02 11 04 02 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d2 9c 20}  //weight: 10, accuracy: Low
        $x_10_3 = {11 03 11 04 11 02 11 04 91 02 11 04 02 6f ?? ?? ?? 0a 5d 28 ?? ?? ?? 06 61 d2 9c 20}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Redline_GMZ_2147901735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GMZ!MTB"
        threat_id = "2147901735"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 08 02 8e 69 5d 1f 1f 59 1f 1f 58 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 1f 09 58 1f 11 58 1f 1a 59 91 61 28 ?? ?? ?? 0a 02 08 20 ?? ?? ?? ?? 58 20 ?? ?? ?? ?? 59 02 8e 69 5d 91 59}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GZZ_2147901892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GZZ!MTB"
        threat_id = "2147901892"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 09 11 07 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 08 02 11 06 8f 1c 00 00 01 25 71 1c 00 00 01 06 11 08 91 61 d2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GZZ_2147901892_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GZZ!MTB"
        threat_id = "2147901892"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 11 40 18 5b 06 11 40 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 00 11 40 18 58 13 40 11 40 06 6f ?? ?? ?? 0a fe 04 13 41 11 41 2d d2}  //weight: 10, accuracy: Low
        $x_1_2 = "FunnyThingAboutThat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GZZ_2147901892_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GZZ!MTB"
        threat_id = "2147901892"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 04 00 00 0a 0a 06 28 ?? ?? ?? 0a 03 50 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 73 08 00 00 0a 0c 08 07 6f ?? ?? ?? 0a 08 18 6f 0a ?? ?? 0a 08 6f ?? ?? ?? 0a 02 50 16 02 50 8e 69 6f ?? ?? ?? 0a 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AMBF_2147902384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AMBF!MTB"
        threat_id = "2147902384"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 1f 10 28 ?? 00 00 2b 1f 20 28 ?? 00 00 2b 28 ?? 00 00 2b 13 02}  //weight: 2, accuracy: Low
        $x_1_2 = "SequenceEqual" ascii //weight: 1
        $x_1_3 = "HMACSHA256" ascii //weight: 1
        $x_1_4 = "AesCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GXZ_2147903447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GXZ!MTB"
        threat_id = "2147903447"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "r.l1nc0in.ru/ma" ascii //weight: 1
        $x_1_2 = "UcblLtkJ+Wsaw2pIk8XvEL+e4N9HkQiF/pHEcaeX18E=" wide //weight: 1
        $x_1_3 = "RH4NsvODKSpfn0rNZAf5ZA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_MVA_2147903728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.MVA!MTB"
        threat_id = "2147903728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 75 0c 00 00 1b 07 17 da 20 05 b6 2c 6d 1e 16 28 23 00 00 06 28 b5 02 00 06 09 28 e2 02 00 06 28 33 00 00 0a a2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_CCHT_2147903966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.CCHT!MTB"
        threat_id = "2147903966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "H4sIAAAAAAAEAAsqzQMAIOI7aAMAAAA=" wide //weight: 1
        $x_1_2 = "H4sIAAAAAAAEAAuuLC5JzdULKs0rycxN1fPMK0ktyi8ITi0qy0xOLQYAcrSvBh4AAAA=" wide //weight: 1
        $x_1_3 = "H4sIAAAAAAAEAHNOzMnJzEt3zs8rS80ryczPAwAbw5LpEQAAAA==" wide //weight: 1
        $x_1_4 = "H4sIAAAAAAAEAAvPzEssyAQA/Q3WvQYAAAA=" wide //weight: 1
        $x_1_5 = "H4sIAAAAAAAEAAsuKU0yNNQLKMovSC0qyUwt1gtKLc4vLUpOLQYAgchYThsAAAA=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GZF_2147904764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GZF!MTB"
        threat_id = "2147904764"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 06 11 03 16 11 03 8e 69 7e ?? ?? ?? 04 28 ?? ?? ?? 06 13 07 20 00 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_KAM_2147904831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.KAM!MTB"
        threat_id = "2147904831"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 11 0b 8f ?? 00 00 01 25 71 ?? 00 00 01 11 ?? 11 ?? 91 61 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ASGE_2147905123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ASGE!MTB"
        threat_id = "2147905123"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b f9 02 08 02 08 91 03 20 be 00 00 00 d6 61}  //weight: 1, accuracy: High
        $x_1_2 = {08 1b 5d 16 fe 01 0d 09 2c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_KAN_2147905940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.KAN!MTB"
        threat_id = "2147905940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 11 13 7e ?? 00 00 04 28 ?? 00 00 06 a5 ?? 00 00 01 61 d2 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GYA_2147913734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GYA!MTB"
        threat_id = "2147913734"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 06 02 06 91 66 d2 9c 02 06 8f 18 00 00 01 25 71 18 00 00 01 20 83 00 00 00 59 d2 81 18 00 00 01 02 06 8f 18 00 00 01 25 71 18 00 00 01 1f 25 58 d2 81 18 00 00 01 00 06 17 58 0a 06 02 8e 69 fe 04 0b 07 2d b9}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_ASGH_2147913852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.ASGH!MTB"
        threat_id = "2147913852"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 02 73 ?? 00 00 0a 0c 08 07 16 73 ?? 00 00 0a 0d 09 73 ?? 00 00 0a 13 04 11 04 02 8e 69 6f ?? 00 00 0a 13 05 de 34 11 04 2c 07 11 04 6f ?? 00 00 0a dc 09 2c 06 09 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
        $x_1_2 = "0E7JCmfMOdgRRSDpDdt0E" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AMAK_2147915535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AMAK!MTB"
        threat_id = "2147915535"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CcJVbqVRWAAeZsJDMMDtd" ascii //weight: 1
        $x_1_2 = "WBidXbUygKejRIubNUXEkzKG" ascii //weight: 1
        $x_1_3 = "OvVpNisigcLwylxoIyTZrXZIrtNG" ascii //weight: 1
        $x_1_4 = "tkvgixfwDPYeqeCCLxKt" ascii //weight: 1
        $x_1_5 = "uZuSqwGhQpLIpTmnR" ascii //weight: 1
        $x_1_6 = "RPeHwzzgkIPNNGQtvHxltWTeR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_Redline_GZN_2147916365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GZN!MTB"
        threat_id = "2147916365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 02 06 02 06 91 66 d2 9c 02 06 8f ?? ?? ?? ?? 25 71 ?? ?? ?? ?? 1f 66 59 d2 81 ?? ?? ?? ?? 02 06 8f ?? ?? ?? ?? 25 71 ?? ?? ?? ?? 20 ?? ?? ?? ?? 58 d2 81 ?? ?? ?? ?? 00 06 17 58 0a 06 02 8e 69 fe 04 0b 07 2d b9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AZ_2147917213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AZ!MTB"
        threat_id = "2147917213"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BfHnbLqBlwrTdgEppis" ascii //weight: 1
        $x_1_2 = "ksJYSIxmonzFiwabChyNV.dll" ascii //weight: 1
        $x_1_3 = "yspsktHhThQyQUnzivyiSLJPmXmN" ascii //weight: 1
        $x_1_4 = "vyrJfcoVrYXVmfzCvxhOJXLeUMRt.dll" ascii //weight: 1
        $x_1_5 = "RcQvWUpoATTmv" ascii //weight: 1
        $x_1_6 = "zpWCwXEbIdwLXXKgUbBHNP.dll" ascii //weight: 1
        $x_1_7 = "KSaORBCsxfgdoKZpTG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AMAZ_2147917718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AMAZ!MTB"
        threat_id = "2147917718"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 02 06 91 66 d2 9c 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 58 d2 81 ?? 00 00 01 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 32 59 d2 81 ?? 00 00 01 00 06 17 58 0a 06 02 8e 69 fe ?? 0b 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AMAZ_2147917718_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AMAZ!MTB"
        threat_id = "2147917718"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 66 d2 9c 02 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 58 d2 81 ?? 00 00 01 02 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 20 ?? 00 00 00 59 d2 81 ?? 00 00 01 00 11 ?? 17 58 13 ?? 11 ?? 02 8e 69 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_VZ_2147917856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.VZ!MTB"
        threat_id = "2147917856"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uWeNaSjRhhVTsORVickacOMHm" ascii //weight: 1
        $x_1_2 = "UVRQYwCqMgJWbCUWNQa.dll" ascii //weight: 1
        $x_1_3 = "SzYQFhcZjOUvTyNzsaaYQNUKcPSm.dll" ascii //weight: 1
        $x_1_4 = "BQyCwQNagzZHTiZOCNPaWwUaDZBWA" ascii //weight: 1
        $x_1_5 = "aBgwTCNaJQMMLMUdORpTjbMBiJdV.dll" ascii //weight: 1
        $x_1_6 = "RKkEhShtVLtvfGQBneJpKFw.dll" ascii //weight: 1
        $x_1_7 = "NxUMwODiCpfvkIVMCZLuBDNPqwe" ascii //weight: 1
        $x_1_8 = "HJqHfuMXddnbByTzTmkXcFONxeSVX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_DZ_2147918621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.DZ!MTB"
        threat_id = "2147918621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SJyWsOeIyeCRkLbnPXnxtqooskJc" ascii //weight: 1
        $x_1_2 = "bbgoGfCSArWHEsAuwFHATsZX.dll" ascii //weight: 1
        $x_1_3 = "YVbtgpjtNbRclFhTIYrXBsnVN" ascii //weight: 1
        $x_1_4 = "BVMAjIJELeyVKjcmBgJQDLIONVFp" ascii //weight: 1
        $x_1_5 = "ixIKjbJjaRAddNbcWUwqW.dll" ascii //weight: 1
        $x_1_6 = "wFubKQAsqitEphEjcuvoHhlZk" ascii //weight: 1
        $x_1_7 = "IVsrvEXQYpsllqRbuSiLlaLVclhp" ascii //weight: 1
        $x_1_8 = "CIWnlNlFCPMnSmvZlxHqgMrNferJX.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_EZ_2147918721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.EZ!MTB"
        threat_id = "2147918721"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ahgFMXgmHjjZKiDAlDYBAtWuKRIj" ascii //weight: 2
        $x_2_2 = "CjGplvJttkKXzzUWSNcPHmDLYrskO" ascii //weight: 2
        $x_1_3 = "oAMfDVwuqpCmOKYDCIPASnquS" ascii //weight: 1
        $x_1_4 = "KkKTLGxmxhCtwWXbwozzpJKpYaxd" ascii //weight: 1
        $x_1_5 = "mLkrpEezCVTNvWORYvQbWVKC" ascii //weight: 1
        $x_1_6 = "FmnkpsaJNjLYhQZYScORStdRIOrkM" ascii //weight: 1
        $x_1_7 = "pCPKvqGZWJUaWOUuMstAnndaWdR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_EZ_2147918721_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.EZ!MTB"
        threat_id = "2147918721"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RsNQyPnVOuKjmnlNLEIRvfGmjdOp" ascii //weight: 1
        $x_1_2 = "VBxVobDIWVMSzNHrULOZgR.dll" ascii //weight: 1
        $x_1_3 = "KiuxAAKZeryiDBOMJiYLE" ascii //weight: 1
        $x_1_4 = "GOwvgrbtIvwwAhXaUHXjYhwqV" ascii //weight: 1
        $x_1_5 = "OHYMjCHFVRLyUXSlgqkFLgDtxeTiw.dll" ascii //weight: 1
        $x_1_6 = "MjYBVyjedCokwGjFrouTVbQ" ascii //weight: 1
        $x_1_7 = "09b8ab1d-9a55-4e28-b71e-36bf5ed7a79a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_FZ_2147919371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.FZ!MTB"
        threat_id = "2147919371"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "YbynWWntwZYNtFWPikgNKwaF.dll" ascii //weight: 2
        $x_2_2 = "qVHNWiCpAcRdiGfgCovyWMIKujhca" ascii //weight: 2
        $x_1_3 = "rFWBQVijoEoSyAHvOLqknlBNpBCqe" ascii //weight: 1
        $x_1_4 = "TLlEypHzEDxcSvFtAuceeJDFFCc" ascii //weight: 1
        $x_1_5 = "DMWtHzlMFvbUwWZGvHZPDKfELuoo" ascii //weight: 1
        $x_1_6 = "KbzgPNwYYKXhzthSOsYwvDRXEAxZ" ascii //weight: 1
        $x_1_7 = "vKchGygUGWaywTJKBMaSnAWoDRRdv" ascii //weight: 1
        $x_1_8 = "QbwnfcbQdJrVEqmyomvdvDSpeT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AMAJ_2147920386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AMAJ!MTB"
        threat_id = "2147920386"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Pevp7LJLoxPBxXMoNPev" ascii //weight: 2
        $x_1_2 = "oYbFUwJLgl9VVKMEUrlc" ascii //weight: 1
        $x_1_3 = "tVKgg0JL0iswWm1qrIG4" ascii //weight: 1
        $x_1_4 = "USNZNBCLEOASSSBHRPVHBYABOMOXP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_PWH_2147920669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.PWH!MTB"
        threat_id = "2147920669"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 08 9a 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 2c 3e 06 08 9a 6f ?? ?? ?? 0a 16 9a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 72 fd 00 00 70 28 ?? ?? ?? 0a 2c 1e 06 08 9a 14 17 8d ?? ?? ?? 01 25 16 02 8c ?? ?? ?? 01 a2 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 0b 08 17 58 0c 08 06 8e 69 32 a4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AMAM_2147920814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AMAM!MTB"
        threat_id = "2147920814"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "pimer.bbbcontents7.My.Resources" ascii //weight: 2
        $x_1_2 = "AANGQSJORDRYOHRARUMLBIPNMSJXQKVZJPXYKABIEYBNODGKZICKKARRLAUXILYGI" ascii //weight: 1
        $x_1_3 = "CSFTFUCNOBMHAOQBUWZCTXTNFOPXKZZELZBYDMBWMSVRY" ascii //weight: 1
        $x_1_4 = "FSEEJKDLTKIFTPLCFRJIZUDCHWTOMCOFNBLLFPBVYERZWGZMXIFHLTXKPBWMRPZQVDSSDZXP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GTL_2147921672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GTL!MTB"
        threat_id = "2147921672"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 0a 17 58 20 ff 00 00 00 5f 13 0a 11 09 11 07 11 0a 95 58 20 ff 00 00 00 5f 13 09 02 11 07 11 0a 8f 52 00 00 01 11 07 11 09 8f 52 00 00 01 28 ?? ?? ?? 06 00 11 07 11 0a 95 11 07 11 09 95 58 20 ff 00 00 00 5f 13 10 11 06 11 08 11 04 11 08 91 11 07 11 10 95 61 28 ?? ?? ?? 0a 9c 11 08 17 58 13 08 00 11 08 6e 11 06 8e 69 6a fe 04 13 11 11 11 2d 8b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_WVAA_2147921693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.WVAA!MTB"
        threat_id = "2147921693"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "NShaping immersive experiences through visionary optics and digital innovation." ascii //weight: 2
        $x_2_2 = "ThinkVision Technologies Inc." ascii //weight: 2
        $x_1_3 = "ThinkVision OptiTech Suite" ascii //weight: 1
        $x_1_4 = "ThinkVision Technologies Trademark" ascii //weight: 1
        $x_1_5 = "$9398dad8-49ac-4487-8ebe-23d0208a9ff5" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_NIT_2147921903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.NIT!MTB"
        threat_id = "2147921903"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 11 05 9a 13 06 00 06 11 06 6f ?? 00 00 06 2c 03 16 2b 03 17 2b 00 2d 08 06 6f ?? 00 00 06 2b 06 18 28 ?? 03 00 06 13 07 11 07 2c 03 16 2b 03 17 2b 00 2d 0a 00 16 28 ?? 03 00 06 0b 2b 14 00 11 05 16 28 ?? 03 00 06 58 13 05 11 05 11 04 8e 69 32 ac}  //weight: 2, accuracy: Low
        $x_1_2 = "GetAllNetworkInterfaces" ascii //weight: 1
        $x_1_3 = "ClientCredentials" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_PAH_2147923240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.PAH!MTB"
        threat_id = "2147923240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 08 04 08 1f 09 5d 9a 28 ?? 00 00 0a 03 08 91 28 ?? 00 00 06 28 ?? 00 00 0a 9c 08 17 d6 0c 08 07 31 dd}  //weight: 10, accuracy: Low
        $x_1_2 = "Ljrorarjdr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GNM_2147923863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GNM!MTB"
        threat_id = "2147923863"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 06 07 6f ?? ?? ?? 0a 13 04 73 ?? ?? ?? 0a 13 05 11 05 11 04 17 73 ?? ?? ?? 0a 13 06 11 06 08 16 08 8e 69 6f ?? ?? ?? 0a 11 05 6f ?? ?? ?? 0a 13 07 dd 33 00 00 00 11 06 39 07 00 00 00 11 06 6f ?? ?? ?? 0a dc 11 05 39 07 00 00 00 11 05 6f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GNE_2147925796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GNE!MTB"
        threat_id = "2147925796"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 07 09 11 08 11 05 11 06 6f ?? ?? ?? 0a 13 08 28 ?? ?? ?? 0a 11 08 6f ?? ?? ?? 0a 17 8d ?? ?? ?? ?? 25 16 1f 24 9d 6f ?? ?? ?? 0a 13 09 08 11 04 1b 6f ?? ?? ?? 0a 13 0a 08 11 04 1c 6f ?? ?? ?? 0a 13 0b 09 11 0a 11 05 11 06 6f ?? ?? ?? 0a 13 0a 09 11 0b 11 05 11 06 6f ?? ?? ?? 0a 13 0b 07 28 ?? ?? ?? 0a 8c ?? ?? ?? ?? 11 09 1a 9a 14 11 09}  //weight: 10, accuracy: Low
        $x_1_2 = "yZCyQRJLLteWtHcxtjGPgL6Ncd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GNT_2147925981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GNT!MTB"
        threat_id = "2147925981"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 05 11 04 11 07 19 6f ?? ?? ?? 0a 11 08 11 09 6f ?? ?? ?? 0a 13 0a 11 05 11 04 11 07 1a 6f ?? ?? ?? 0a 11 08 11 09 6f ?? ?? ?? 0a 13 0b 11 0a 2c 07 11 0b 14 fe 01 2b 01 17 13 13 11 13 2c 05 dd ?? ?? ?? ?? 28 ?? ?? ?? 0a 11 0b 6f ?? ?? ?? 0a 17 8d ?? ?? ?? ?? 25 16 1f 24 9d 6f ?? ?? ?? 0a 13 0c 11 0c 2c 0a 11 0c 8e 69 1f 0d fe 04 2b 01 17 13 14 11 14 2c 05}  //weight: 10, accuracy: Low
        $x_1_2 = "Hyderabad.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AB_2147935991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AB!MTB"
        threat_id = "2147935991"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 25 00 00 01 0a 02 1b 06 16 02 8e 69 1b 59 28 63 00 00 0a 06 16 14 28 33 00 00 06 0b 25 03 6f 64 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AB_2147935991_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AB!MTB"
        threat_id = "2147935991"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "work\\ImageResizeTest\\geo-elevation.png" ascii //weight: 2
        $x_1_2 = "createdecryptor" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_5 = "debuggernonusercodeattribute" ascii //weight: 1
        $x_1_6 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_GTZ_2147937159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.GTZ!MTB"
        threat_id = "2147937159"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1b 11 06 8f ?? ?? ?? 01 25 47 09 11 06 58 1f 11 5a 20 00 01 00 00 5d d2 61 d2 52 09 1f 1f 5a 08 75 ?? ?? ?? 1b 11 06 91 58 20 00 01 00 00 5d 0d 11 06 17 58 13 06 11 06 08 75 ?? ?? ?? 1b 8e 69 32 b9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redline_AYVA_2147942924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redline.AYVA!MTB"
        threat_id = "2147942924"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 2b 24 2b 26 16 2b 26 8e 69 2b 25 2b 2a 2b 2c 2b 31 2b 33 2b 38 11 06 03 72 ?? ?? 00 70 28 ?? ?? 00 06 17 0b de 5c 11 05 2b d8 06 2b d7 06 2b d7 6f ?? 00 00 0a 2b d4 11 05 2b d2 6f ?? 00 00 0a 2b cd 11 04 2b cb 6f ?? 00 00 0a 2b c6 13 06 2b c4}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

