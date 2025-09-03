rule Trojan_MSIL_Rozena_MA_2147827122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.MA!MTB"
        threat_id = "2147827122"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 8e 69 8d ?? ?? ?? 01 0c 16 13 09 2b 17 00 08 11 09 07 11 09 9a 1f 10 28 ?? ?? ?? 0a 9c 00 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d dc 16 08 8e 69 20 00 30 00 00 1a 28 ?? ?? ?? 06 0d 08 16 09 08 8e 69 28 ?? ?? ?? 0a 00 7e ?? ?? ?? 0a 13 04 16 13 05 7e ?? ?? ?? 0a 13 06 09 20 00 10 00 00 1f 20 12 07 28 ?? ?? ?? 06 13 08 16 16 09 11 06 16 12 05 28 ?? ?? ?? 06 13 04 11 04 15 28 ?? ?? ?? 06 26 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateThread" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "WaitForSingleObject" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_APA_2147833819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.APA!MTB"
        threat_id = "2147833819"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 06 8e 69 8d 18 00 00 01 0b 16 0c 2b 11 00 07 08 06 08 93 28 ?? ?? ?? 0a 9c 00 08 17 58 0c 08 07 8e 69 fe 04 0d 09 2d e5}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_AVHI_2147836988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.AVHI!MTB"
        threat_id = "2147836988"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0c 11 0d 11 0c 11 0d 91 6e 11 0d 6a 59 20 ff 00 00 00 6a 5f d2 9c 11 0d 17 58 13 0d 11 0d 11 0c 8e 69}  //weight: 2, accuracy: High
        $x_1_2 = "ZwQueryInformationProcess" ascii //weight: 1
        $x_1_3 = "CreateProcess" ascii //weight: 1
        $x_1_4 = "C:\\Windows\\System32\\svchost.exe" wide //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
        $x_1_6 = "ResumeThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPQ_2147837218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPQ!MTB"
        threat_id = "2147837218"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {11 06 17 58 13 06 18 13 08 2b 0d 11 06 11 08 5d 2c 0c 11 08 17 58 13 08 11 08 11 06 31 ed 11 08 11 06 33 06 11 07 17 58 13 07 11 07 11 05 32 d0}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_AE_2147837449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.AE!MTB"
        threat_id = "2147837449"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AV Evasion2 +heuristic" wide //weight: 2
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "GetCurrentProcess" ascii //weight: 1
        $x_1_4 = "ToCharArray" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPA_2147842634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPA!MTB"
        threat_id = "2147842634"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 03 8e 69 20 00 10 00 00 1f 40 28 ?? ?? ?? 06 0a 06 7e ?? ?? ?? 0a 28 ?? ?? ?? 0a 2c 0b 28 ?? ?? ?? 0a 73 1a 00 00 0a 7a 03 16 06 03 8e 69 28 ?? ?? ?? 0a 06}  //weight: 3, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_AZR_2147844462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.AZR!MTB"
        threat_id = "2147844462"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 16 13 37 2b 15 00 08 11 37 07 11 37 93 28 15 00 00 0a 9c 00 11 37 17 58 13 37 11 37 08 8e 69 fe 04 13 38 11 38 2d de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_AZR_2147844462_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.AZR!MTB"
        threat_id = "2147844462"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DropperMsfstaged.exe" wide //weight: 1
        $x_1_2 = "1764ee23-1049-4167-b8be-038866f57828" ascii //weight: 1
        $x_1_3 = "Z:\\visualstudio\\OSEP\\DropperMsfstaged\\obj\\x64\\Debug\\DropperMsfstaged.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_PSJS_2147844534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.PSJS!MTB"
        threat_id = "2147844534"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hsufw4ev" ascii //weight: 2
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "DebuggingModes" ascii //weight: 1
        $x_1_4 = "explore.exe" ascii //weight: 1
        $x_1_5 = "CreateThread" ascii //weight: 1
        $x_1_6 = "|myself.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NR_2147845588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NR!MTB"
        threat_id = "2147845588"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 01 00 00 06 0b 16 07 06 28 ?? 00 00 0a 7e ?? 00 00 0a 16 07 7e ?? 00 00 0a 16 7e ?? 00 00 0a 28 ?? 00 00 06 15}  //weight: 5, accuracy: Low
        $x_1_2 = "OffensiveSharp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NR_2147845588_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NR!MTB"
        threat_id = "2147845588"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1f 28 28 2a 00 00 0a 6e 06 1f 2c 28 ?? ?? ?? 0a 6e 0c 28 ?? ?? ?? 06 6e 08 28 ?? ?? ?? 06 6e 0c 20 ?? ?? ?? 00 6a 5a 08 20 ?? ?? ?? 00 6a 5a}  //weight: 5, accuracy: Low
        $x_1_2 = "CSharpLoaderAESkey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NR_2147845588_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NR!MTB"
        threat_id = "2147845588"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {28 13 00 00 0a 72 70 07 00 70 6f 14 00 00 0a 0b 28 ?? 00 00 0a 72 b2 07 00 70 6f 14 00 00 0a 0c 28 ?? 00 00 0a 07 08 28 ?? 00 00 06 0d 09 8e 69 13 04}  //weight: 3, accuracy: Low
        $x_1_2 = "EvasionSuite.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NR_2147845588_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NR!MTB"
        threat_id = "2147845588"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 27 00 00 0a 1f 28 58 13 0b 11 0a 11 0b 28 ?? ?? ?? 0a 6e 11 09 28 ?? ?? ?? 0a 58 28 ?? ?? ?? 0a 13 0c 20 ?? ?? ?? 00 8d ?? ?? ?? 01 25 d0 ?? ?? ?? 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "hasnainwins" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NR_2147845588_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NR!MTB"
        threat_id = "2147845588"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 04 8e 69 13 05 7e ?? 00 00 0a 20 00 10 00 00 20 00 30 00 00 1f 40 28 ?? 00 00 06 13 06 11 04 16 11 06 11 05}  //weight: 3, accuracy: Low
        $x_3_2 = {7e 13 00 00 0a 16 11 06 7e ?? 00 00 0a 16 7e ?? 00 00 0a 28 ?? 00 00 06 13 07 11 07 15 28 ?? 00 00 06 26}  //weight: 3, accuracy: Low
        $x_1_3 = "shanekhantaun9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_RPQ_2147846024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.RPQ!MTB"
        threat_id = "2147846024"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZPlanTools" ascii //weight: 1
        $x_1_2 = "ZPlanDemo" ascii //weight: 1
        $x_1_3 = "GetCoce" ascii //weight: 1
        $x_1_4 = "GetFileNum" ascii //weight: 1
        $x_1_5 = "RSADecrypt" ascii //weight: 1
        $x_1_6 = "DEncryption" ascii //weight: 1
        $x_1_7 = "VirtualAlloc" ascii //weight: 1
        $x_1_8 = "CreateThread" ascii //weight: 1
        $x_1_9 = "WaitForSingleObject" ascii //weight: 1
        $x_1_10 = "Concat" ascii //weight: 1
        $x_1_11 = "FromBase64String" ascii //weight: 1
        $x_1_12 = "ToArray" ascii //weight: 1
        $x_1_13 = "ToBase64String" ascii //weight: 1
        $x_1_14 = "<RSAKeyValue>" wide //weight: 1
        $x_1_15 = "<Exponent>" wide //weight: 1
        $x_1_16 = "<InverseQ>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NRE_2147846192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NRE!MTB"
        threat_id = "2147846192"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 00 30 00 00 1f 40 28 ?? ?? 00 06 0c 07 16 08 07 8e 69 28 ?? ?? 00 0a 00 7e ?? ?? 00 0a 16 08 7e ?? ?? 00 0a 16 7e ?? ?? 00 0a 28 ?? ?? 00 06}  //weight: 5, accuracy: Low
        $x_1_2 = "lpStartAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_ARZ_2147846523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.ARZ!MTB"
        threat_id = "2147846523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 01 00 00 70 0a 28 01 00 00 0a 16 9a 28 02 00 00 0a 06 28 03 00 00 0a 39 00 00 00 00 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_ARZ_2147846523_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.ARZ!MTB"
        threat_id = "2147846523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 13 16 2b 15 07 11 16 07 11 16 91 20 fa 00 00 00 61 d2 9c 11 16 17 58 13 16 11 16 07 8e 69 32 e4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_ARZ_2147846523_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.ARZ!MTB"
        threat_id = "2147846523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0b 16 13 06 2b 18 07 11 06 07 11 06 91 1f 22 61 20 ff 00 00 00 5f d2 9c 11 06 17 58 13 06 11 06 07 8e 69 32 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_ARZ_2147846523_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.ARZ!MTB"
        threat_id = "2147846523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 06 16 08 07 28 ?? ?? ?? 0a 7e 02 00 00 0a 16 08 7e 02 00 00 0a 16 7e 02 00 00 0a 28 ?? ?? ?? 06 0d 09 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_ARZ_2147846523_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.ARZ!MTB"
        threat_id = "2147846523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 07 16 08 6e 28 ?? ?? ?? 0a 07 8e 69 28 ?? ?? ?? 0a 00 7e 0c 00 00 0a 0d 16 13 04 7e 0c 00 00 0a 13 05 16 16 08 11 05 16 12 04 28 ?? ?? ?? 06 0d 09 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_ARZ_2147846523_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.ARZ!MTB"
        threat_id = "2147846523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 16 08 8e 69 7e ?? 00 00 04 7e ?? 00 00 04 28 ?? 00 00 06 0d 08 16 09 6e 28 ?? 00 00 0a 08 8e 69 28 ?? 00 00 0a 16 16 09 07 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_ARZ_2147846523_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.ARZ!MTB"
        threat_id = "2147846523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 07 2b 14 07 11 07 8f ?? 00 00 01 25 47 08 61 d2 52 11 07 17 58 13 07 11 07 07 8e 69 32 e5}  //weight: 2, accuracy: Low
        $x_1_2 = "Desktop\\code\\Encryption\\Encryption\\obj\\x64\\Release\\Encryption.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_ARZ_2147846523_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.ARZ!MTB"
        threat_id = "2147846523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 06 8e 69 8d 15 00 00 01 0b 16 0c 2b 0f 07 08 06 08 93 28 ?? ?? ?? 0a 9c 08 17 58 0c 08 07 8e 69 32 eb}  //weight: 2, accuracy: Low
        $x_1_2 = "nietv567" wide //weight: 1
        $x_1_3 = "HKEY_CURRENT_USER\\Software\\LoyeinDBServiceAPI" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_GIF_2147846645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.GIF!MTB"
        threat_id = "2147846645"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dCAkdmFyX2NvZGUuQ291bnQ7ICR4KyspIHs" ascii //weight: 1
        $x_1_2 = "9ICR2YXJfY29kZVskeF0gLWJ4b3IgNjkgLWJ4b3IgM" ascii //weight: 1
        $x_1_3 = "spzzcify thzz -zzxtract" ascii //weight: 1
        $x_1_4 = "-whatt" ascii //weight: 1
        $x_1_5 = "-extdummt" ascii //weight: 1
        $x_1_6 = "out-string" ascii //weight: 1
        $x_1_7 = "PowerShell" ascii //weight: 1
        $x_1_8 = "zzxtraction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPC_2147847782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPC!MTB"
        threat_id = "2147847782"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 17 58 0b 08 06 8e 69 17 58 33 11 06 08 8f ?? ?? ?? 01 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 08 06 8e 69 2e 1b 06 08 8f ?? ?? ?? 01 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 08 17 58 0c 08 06 8e 69 32 b8}  //weight: 1, accuracy: Low
        $x_1_2 = "anti-virus.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPCS_2147847822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPCS!MTB"
        threat_id = "2147847822"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 08 08 8e 69 32 e7 09 8e 69 13 04 7e ?? ?? ?? 0a 11 04 20 00 30 00 00 1f 40 28 ?? ?? ?? 06 13 05 09 16 11 05}  //weight: 1, accuracy: Low
        $x_1_2 = "csharp_runner.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_EN_2147849717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.EN!MTB"
        threat_id = "2147849717"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d8b7f7a6\\3bff7db7\\App_Web_i0gxoa31.pdb" ascii //weight: 1
        $x_1_2 = "/CloudFlow/TempFile/aspxweb.aspx" wide //weight: 1
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "HttpSessionState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_PSRM_2147850749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.PSRM!MTB"
        threat_id = "2147850749"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 72 01 00 00 70 0a 73 0f 00 00 0a 0b 14 0c 00 07 06 6f 10 00 00 0a 0c 00 de 1c 13 06 00 72 49 00 00 70 11 06 6f 11 00 00 0a 28 12 00 00 0a 28 13 00 00 0a 00 de 53}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_RDC_2147851446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.RDC!MTB"
        threat_id = "2147851446"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 04 07 11 04 91 20 ff 00 00 00 61 1f 11 58 d2 9c 11 04 17 58 13 04 11 04 07 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_PSTC_2147851566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.PSTC!MTB"
        threat_id = "2147851566"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {35 00 00 0a 6f ?? 00 00 0a d0 04 00 00 02 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 74 04 00 00 02 13 04 2b 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_RDB_2147851686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.RDB!MTB"
        threat_id = "2147851686"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 09 00 00 0a 06 8e 69 6a 28 0a 00 00 0a 7e 03 00 00 04 7e 04 00 00 04 28 01 00 00 06 0b 06 16 07 06 8e 69 28 0b 00 00 0a 00 7e 09 00 00 0a 0c 7e 09 00 00 0a 7e 0c 00 00 0a 07 7e 09 00 00 0a 16 12 02 28 02 00 00 06 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPXD_2147851695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPXD!MTB"
        threat_id = "2147851695"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {07 11 06 07 11 06 91 1e 59 20 ?? ?? ?? 00 5f d2 9c 11 06 17 58 13 06 11 06 07 8e 69 32 e2}  //weight: 3, accuracy: Low
        $x_3_2 = "192.168.45.237" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Rozena_PSTV_2147852142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.PSTV!MTB"
        threat_id = "2147852142"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 28 0f 00 00 0a 0b 16 0c 2b 17 07 08 9a 0a 02 17 58 10 00 02 17 31 06 06 6f 10 00 00 0a 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_PSUH_2147852523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.PSUH!MTB"
        threat_id = "2147852523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 01 00 00 70 28 ?? 00 00 0a 0a 7e 14 00 00 0a 06 8e 69 20 00 10 00 00 1f 40 28 ?? 00 00 06 0b 06 16 07 06 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NRZ_2147852936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NRZ!MTB"
        threat_id = "2147852936"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 06 07 11 06 91 18 59 20 ?? 00 00 00 5f d2 9c 11 06 17 58 13 06 11 06 07 8e 69}  //weight: 5, accuracy: Low
        $x_5_2 = {28 01 00 00 06 0d 07 16 09 08 28 ?? 00 00 0a 7e ?? 00 00 0a 16 09 7e ?? 00 00 0a 16 7e ?? 00 00 0a 28 ?? 00 00 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_CXJP_2147888597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.CXJP!MTB"
        threat_id = "2147888597"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 0b 09 11 0b 91 18 59 20 ?? ?? ?? ?? 5f d2 9c 00 11 0b 17 58 13 0b 11 0b 09 8e 69 fe 04 13 0c 11 0c 2d da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_AT_2147888605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.AT!MTB"
        threat_id = "2147888605"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 07 2b 36 09 11 07 07 11 07 91 1f 42 61 d2 9c 09 11 07 07 11 07 91 1f 43 61 d2 9c 09 11 07 07 11 07 91 1f 44 61 d2 9c 09 11 07 07 11 07 91 1f 45 61 d2 9c 11 07 1a 58 13 07 11 07 08 32 c5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_AP_2147888613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.AP!MTB"
        threat_id = "2147888613"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 06 16 13 17 2b 4d 16 13 18 2b 3c 08 11 18 11 17 6f ?? ?? ?? 0a 13 19 7e 04 00 00 04 11 19 12 1a 6f ?? ?? ?? 0a 2c 0e 11 05 11 06 25 17 58 13 06 11 1a 9d 2b 0c 11 05 11 06 25 17 58 13 06 1f 30 9d 11 18 17 58 13 18 11 18 11 04 32 be}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_AN_2147888784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.AN!MTB"
        threat_id = "2147888784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0b 16 13 04 2b 18 07 11 04 07 11 04 91 1f 11 59 20 ff 00 00 00 5f d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_AR_2147888800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.AR!MTB"
        threat_id = "2147888800"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 20 ff 01 0f 00 28 ?? ?? ?? 06 72 39 00 00 70 0b 25 15 19 16 07 14 14 14 14 14 14 28 ?? ?? ?? 06 26 16 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_GP_2147888818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.GP!MTB"
        threat_id = "2147888818"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 09 02 09 02 09 91 03 09 07 5d 91 61 d2 25 13 04 9c 11 04 9c 09 17 58 0d 09 06}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_CXJQ_2147888916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.CXJQ!MTB"
        threat_id = "2147888916"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0c 16 06 8e 69 20 ?? ?? ?? ?? 1f 40 28 ?? ?? ?? ?? 0d 06 16 09 6e 28 ?? ?? ?? ?? 06 8e 69 28 ?? ?? ?? ?? 00 7e ?? ?? ?? ?? 13 04 16 16 09 11 04 16 12 02 28 ?? ?? ?? ?? 0b 07 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_CXJR_2147888917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.CXJR!MTB"
        threat_id = "2147888917"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 06 03 8e 69 5d 91 61 d2 81 ?? ?? ?? ?? 00 06 17 58 0a 06 02 8e 69 fe 04 0c 08 2d d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_PSWS_2147890092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.PSWS!MTB"
        threat_id = "2147890092"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 20 c5 00 00 00 28 ?? 00 00 0a 13 05 1c 13 06 11 04 8e 69 8d 1d 00 00 01 13 07 16 13 0b 2b 22}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPDI_2147890124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPDI!MTB"
        threat_id = "2147890124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 01 00 00 70 0a 06 28 ?? ?? ?? 0a 0b 72 d4 04 00 70 0c 28 ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 0d 07 09 28 ?? ?? ?? 06 13 04 16 11 04 8e 69 7e 01 00 00 04 7e 02 00 00 04 28 ?? ?? ?? 06 13 05 11 04 16 11 05}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_AC_2147892100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.AC!MTB"
        threat_id = "2147892100"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 8e 69 0c 07 8e 69 8d ?? ?? ?? 01 0d 16 13 07 2b 17 09 11 07 07 11 07 91 18 59 20 ff 00 00 00 5f d2 9c 11 07 17 58 13 07 11 07 07 8e 69 32 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPAP_2147892265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPAP!MTB"
        threat_id = "2147892265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 16 11 04 08 16 12 01 28 ?? ?? ?? 06 0a 06 15 28 ?? ?? ?? 06 26 2b 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NRO_2147892286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NRO!MTB"
        threat_id = "2147892286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 72 86 12 00 70 28 ?? 00 00 06 0d 73 ?? 00 00 0a 13 04 06 28 ?? 00 00 0a 73 ?? 00 00 0a 13 05 11 05 11 04 08 09 6f ?? 00 00 0a 16 73 ?? 00 00 0a 13 06 11 06 73 ?? 00 00 0a 13 07 11 07}  //weight: 5, accuracy: Low
        $x_1_2 = "CalistirmaFonksiyonu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NRO_2147892286_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NRO!MTB"
        threat_id = "2147892286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 d3 00 00 70 0b 73 ?? ?? ?? 0a 13 08 11 08 07 6f ?? ?? ?? 0a 0a de 0c 11 08 2c 07 11 08 6f ?? ?? ?? 0a dc 06 28 ?? ?? ?? 0a 02 8e 69 8d 1c 00 00 01 0c 16 13 09 2b 17 08 11 09 02 11 09 91 18 59 20 ?? ?? ?? 00 5f d2 9c 11 09 17 58 13 09 11 09 02 8e 69 32 e2 08 8e 69 26 28 ?? ?? ?? 06 7e ?? ?? ?? 0a 28 ?? ?? ?? 06 0d 7e ?? ?? ?? 0a 20 ?? ?? ?? 00 20 ?? ?? ?? 00 1a 16 28 ?? ?? ?? 06 13 04 06 8e 69 28 ?? ?? ?? 0a 13 05 06 16 11 05 06 8e 69 28 ?? ?? ?? 0a 11 04 11 05 06 8e 69 28 ?? ?? ?? 06}  //weight: 5, accuracy: Low
        $x_1_2 = "MailSlotWithTest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_ARE_2147892634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.ARE!MTB"
        threat_id = "2147892634"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 06 16 07 06 8e 69 28 ?? 00 00 0a 00 7e ?? 00 00 0a 0c 7e ?? 00 00 0a 7e ?? 00 00 0a 07 7e ?? 00 00 0a 16 12 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_KAA_2147892847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.KAA!MTB"
        threat_id = "2147892847"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 08 11 17 08 11 17 91 20 ?? 00 00 00 61 d2 9c 00 11 17 17 58 13 17 11 17 08 8e 69 fe 04 13 18 11 18 2d dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPT_2147893935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPT!MTB"
        threat_id = "2147893935"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {7e 13 00 00 0a 0d 16 13 04 16 08 8e 69 20 ?? ?? ?? 00 1f 40 28 ?? ?? ?? 06 13 05 08 16 11 05 6e 28 ?? ?? ?? 0a 08 8e 69}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SSVP_2147893936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SSVP!MTB"
        threat_id = "2147893936"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {07 11 06 07 11 06 91 1e 59 20 ?? ?? ?? 00 5f d2 9c 11 06 17 58 13 06 11 06 07 8e 69 32 e2}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SK_2147894987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SK!MTB"
        threat_id = "2147894987"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 06 8f 01 00 00 01 25 47 03 06 03 8e 69 5d 91 61 d2 52 06 17 58 0a 06 02 8e 69 3f e0 ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_CCDP_2147895219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.CCDP!MTB"
        threat_id = "2147895219"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 08 8e 69 33 02 16 0d 07 11 06 06 11 06 91 08 09 93 28 ?? ?? ?? ?? 61 d2 9c 09 17 58 0d 11 06 17 58 13 06 11 06 06 8e 69 32 d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPQL_2147895366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPQL!MTB"
        threat_id = "2147895366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 05 07 11 05 91 18 59 20 ?? ?? ?? 00 5f d2 9c 11 05 17 58 13 05 11 05 07 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPQB_2147895373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPQB!MTB"
        threat_id = "2147895373"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 06 9a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 07 08 11 06 11 07 9c 00 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 08 11 08 2d d5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPQI_2147895485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPQI!MTB"
        threat_id = "2147895485"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 09 11 0a 9a 13 0b 00 7e ?? ?? ?? 04 11 08 11 0b 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 11 08 17 58 13 08 00 11 0a 17 58 13 0a 11 0a 11 09 8e 69 32 c3}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPQA_2147895630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPQA!MTB"
        threat_id = "2147895630"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {fe 0c 28 01 00 00 fe 0c 29 01 00 00 9a fe 0e 2a 01 00 00 00 7e ?? ?? ?? 04 11 c3 fe 0c 2a 01 00 00 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 11 c3 17 58 13 c3 00 fe 0c 29 01 00 00 17 58 fe 0e 29 01 00 00 fe 0c 29 01 00 00 fe 0c 28 01 00 00 8e 69 32 a3}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPQN_2147895918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPQN!MTB"
        threat_id = "2147895918"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 0a 11 0b 9a 13 0c 00 7e ?? ?? ?? 04 11 09 11 0c 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 11 09 17 58 13 09 00 11 0b 17 58 13 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_PTCB_2147896768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.PTCB!MTB"
        threat_id = "2147896768"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 6f 0c 00 00 0a 26 07 6f 0d 00 00 0a 02 6f 0e 00 00 0a 07 6f 0d 00 00 0a 6f 0f 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_MBFN_2147898449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.MBFN!MTB"
        threat_id = "2147898449"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 9a 16 18 6f ?? 00 00 0a 25 20 03 02 00 00 28 ?? 00 00 0a 1f 10 5d 0d 20 03 02 00 00 28 ?? 00 00 0a 1f 10 5b 13 04 09 1f 10 5a 11 04 58 13 05 06 08}  //weight: 1, accuracy: Low
        $x_1_2 = {30 00 78 00 38 00 45 00 2c 00 30 00 78 00 38 00 38 00 2c 00 30 00 78 00 35 00 37 00 2c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_MBFO_2147898465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.MBFO!MTB"
        threat_id = "2147898465"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vny0veTCs6j3R/oZhaczw92bv/On" wide //weight: 1
        $x_1_2 = "v+r6mnPku3/PaEibSl7dM" wide //weight: 1
        $x_1_3 = {74 00 65 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 00 00 2a}  //weight: 1, accuracy: High
        $x_1_4 = "79307930" wide //weight: 1
        $x_1_5 = "DESCryptoServiceProvider" ascii //weight: 1
        $x_1_6 = "Byte8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_ARA_2147899457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.ARA!MTB"
        threat_id = "2147899457"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 02 07 91 03 61 d2 9c 07 17 58 0b 07 02 8e 69 32 ed}  //weight: 2, accuracy: High
        $x_2_2 = "ShellcodeRunner_evasion.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_ARA_2147899457_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.ARA!MTB"
        threat_id = "2147899457"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 49 06 07 06 8e 69 5d 93 61 d1 53 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d dd}  //weight: 2, accuracy: High
        $x_2_2 = "://jcxjg.fun/test/de_shellcode" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_ARA_2147899457_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.ARA!MTB"
        threat_id = "2147899457"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 0d 09 2d e1}  //weight: 2, accuracy: High
        $x_1_2 = "InvokeShellcodecurrentProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_ARA_2147899457_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.ARA!MTB"
        threat_id = "2147899457"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 09 06 09 91 1f 22 59 1f 4a 61 20 ff 00 00 00 5f d2 9c 09 17 58 0d 09 06 8e 69 32 e3}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualAllocExNuma" ascii //weight: 1
        $x_1_3 = "CreateThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_ARA_2147899457_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.ARA!MTB"
        threat_id = "2147899457"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0a 2b 21 00 02 06 8f ?? ?? ?? 01 25 71 ?? ?? ?? 01 03 06 03 8e 69 5d 91 61 d2 81 ?? ?? ?? 01 00 06 17 58 0a 06 02 8e 69 fe 04 0c 08 2d d5 02 0b 2b 00 07 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "CreateThread" ascii //weight: 1
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_ARA_2147899457_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.ARA!MTB"
        threat_id = "2147899457"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 08 11 0a 08 11 0a 91 19 8d ?? ?? ?? 01 25 d0 ?? ?? ?? 04 28 ?? ?? ?? 0a 11 0a 19 5d 91 61 d2 9c 00 11 0a 17 58 13 0a 11 0a 08 8e 69 fe 04 13 0b 11 0b 2d cb}  //weight: 2, accuracy: Low
        $x_2_2 = "SELECT * FROM AntivirusProduct" wide //weight: 2
        $x_2_3 = "Windows Defender" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SXP_2147899993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SXP!MTB"
        threat_id = "2147899993"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 11 09 08 11 09 91 18 59 20 ?? ?? ?? 00 5f d2 9c 00 11 09 17 58 13 09 11 09 08 8e 69 fe 04 13 0a 11 0a 2d da}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_AAAY_2147900083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.AAAY!MTB"
        threat_id = "2147900083"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0a 2b 17 02 06 8f ?? 00 00 01 25 47 03 06 03 8e 69 5d 91 61 d2 52 06 17 58 0a 06 02 8e 69 32 e3}  //weight: 2, accuracy: Low
        $x_2_2 = {07 09 06 5a 08 58 02 08 06 5a 09 58 91 9c 09 17 58 0d 09 06 32 ea}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SXXP_2147901116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SXXP!MTB"
        threat_id = "2147901116"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 08 06 08 93 28 ?? ?? ?? 0a 9c 00 08 17 58 0c 08 07 8e 69 fe 04 0d 09 3a ca fc ff ff}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NBL_2147901469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NBL!MTB"
        threat_id = "2147901469"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 07 02 07 91 28 10 00 00 0a 03 6f 11 00 00 0a 07 28 10 00 00 0a 03 6f 11 00 00 0a 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 d3 06 2a}  //weight: 1, accuracy: High
        $x_1_2 = "xorEncDec" ascii //weight: 1
        $x_1_3 = "avbypass" ascii //weight: 1
        $x_1_4 = "avbypass.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_EEAA_2147902786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.EEAA!MTB"
        threat_id = "2147902786"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 08 06 08 91 1b 58 20 ff 00 00 00 5f d2 9c 08 17 58 0c 08 06 8e 69 3f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPYU_2147902889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPYU!MTB"
        threat_id = "2147902889"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 8e 69 20 ?? ?? ?? 00 1f 40 28 ?? ?? ?? 06 13 05 11 05}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_ERAA_2147903180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.ERAA!MTB"
        threat_id = "2147903180"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 13 11 17 11 13 11 17 91 18 61 20 ff 00 00 00 5f d2 9c 11 17 17 58 13 17 11 17 11 13 8e 69 32 df}  //weight: 5, accuracy: High
        $x_5_2 = {16 0c 2b 0d 07 08 06 08 91 03 61 d2 9c 08 17 58 0c 08 06 8e 69 32 ed}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Rozena_FGAA_2147903194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.FGAA!MTB"
        threat_id = "2147903194"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 07 06 6f ?? 00 00 0a 16 73 ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 20 00 04 00 00 8d ?? 00 00 01 13 04 2b 0b 09 11 04 16 11 05 6f ?? 00 00 0a 08 11 04 16 11 04 8e 69 6f ?? 00 00 0a 25 13 05 16 30 e2 09 6f ?? 00 00 0a 13 06 de 28}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_FIAA_2147903196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.FIAA!MTB"
        threat_id = "2147903196"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 16 06 8e 69 7e ?? 00 00 04 7e ?? 00 00 04 28 ?? 00 00 06 0c 06 16 08 6e 28 ?? 00 00 0a 06 8e 69 28 ?? 00 00 0a 7e ?? 00 00 0a 26 16 0d 7e ?? 00 00 0a 13 04 16 16 08 11 04 16 12 03 28 ?? 00 00 06 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_FJAA_2147903197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.FJAA!MTB"
        threat_id = "2147903197"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 8e 69 0c 7e ?? 00 00 0a 20 00 10 00 00 20 00 30 00 00 1f 40 28 ?? 00 00 06 0d 16 09 08 28 ?? 00 00 0a 7e ?? 00 00 0a 16 09 7e ?? 00 00 0a 16 7e ?? 00 00 0a 28 ?? 00 00 06 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPYX_2147903234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPYX!MTB"
        threat_id = "2147903234"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8e 69 0b 7e ?? ?? ?? 0a 20 00 10 00 00 20 00 30 00 00 1f 40 28 ?? ?? ?? 06 0c 06 16 08}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPZY_2147903695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPZY!MTB"
        threat_id = "2147903695"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {09 8e 69 13 04 7e ?? ?? ?? 0a 20 ?? ?? ?? 00 20 ?? ?? ?? 00 1f 40 28 ?? ?? ?? 06 13 05 09}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPPX_2147905127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPPX!MTB"
        threat_id = "2147905127"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 07 91 08 61 d2 9c 11 07 17 58 13 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_HYAA_2147905245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.HYAA!MTB"
        threat_id = "2147905245"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 11 05 07 11 05 91 1f 41 61 20 ff 00 00 00 5f d2 9c 11 05 17 58 13 05 11 05 07 8e 69 32 d0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_KAC_2147906222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.KAC!MTB"
        threat_id = "2147906222"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 06 5d 94 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 ?? 08 09 11 ?? d2 9c 00 09 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_KAD_2147906223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.KAD!MTB"
        threat_id = "2147906223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0d 06 07 08 03 58 09 59 1f 1a 5d 09 58 d1 9d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_HNS_2147906408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.HNS!MTB"
        threat_id = "2147906408"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2e 00 65 00 78 00 65 00 00 ?? ?? 53 00 74 00 61 00 72 00 74 00 65 00 64 00 20 00 27 00 [0-18] 2e 00 65 00 78 00 65 00 27 00 20 00 69 00 6e 00 20 00 61 00 20 00 73 00 75}  //weight: 2, accuracy: Low
        $x_2_2 = {00 2e 00 65 00 78 00 65 00 27 00 20 00 69 00 6e 00 20 00 61 00 20 00 73 00 75 00 73 00 70 00 65 00 6e 00 64 00 65 00 64 00 20 00 73 00 74 00 61 00 74 00 65 00 20 00 77 00 69 00 74 00 68 00 20 00 50 00 49 00 44 00 20 00 7b 00 30 00 7d 00 2e 00 20 00 53 00 75 00 63 00 63 00 65 00 73 00 73 00}  //weight: 2, accuracy: High
        $x_2_3 = {00 43 52 45 41 54 45 5f 53 55 53 50 45 4e 44 45 44 00}  //weight: 2, accuracy: High
        $x_2_4 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 6c 70 43 75 72 72 65 6e 74 44 69 72 65 63 74 6f 72 79 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_Rozena_HNS_2147906408_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.HNS!MTB"
        threat_id = "2147906408"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8e 69 7e 01 00 00 04 7e 02 00 00 04 28 ?? 00 00 06 ?? ?? 16 ?? 6e 28 ?? 00 00 0a ?? 8e 69 28 ?? 00 00 [0-2] 7e ?? 00 00 0a ?? 16 0d 7e ?? 00 00 0a 13 04 16 16 ?? 11 04 16 12 03 28 ?? 00 00 [0-3] 15 28 ?? 00 00 06 26 2a}  //weight: 10, accuracy: Low
        $x_10_2 = {13 04 16 16 07 11 04 16 12 03 28 ?? 00 00 06 0c 08 15 28 ?? 00 00 06 26 17 00 [0-11] 06 8e 69 28 ?? 00 00 ?? [0-3] 7e ?? ?? ?? ?? 0c 16 0d}  //weight: 10, accuracy: Low
        $x_2_3 = {00 45 58 45 43 55 54 45 52 45 41 44 57 52 49 54 45 00}  //weight: 2, accuracy: High
        $x_2_4 = {00 50 41 47 45 5f 45 58 45 43 55 54 45 5f 52 45 41 44 57 52 49 54 45 00}  //weight: 2, accuracy: High
        $x_2_5 = {00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 00}  //weight: 2, accuracy: High
        $x_2_6 = {00 43 72 65 61 74 65 54 68 72 65 61 64 00}  //weight: 2, accuracy: High
        $x_2_7 = {00 57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Rozena_HNS_2147906408_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.HNS!MTB"
        threat_id = "2147906408"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 64 6c 6c 00 57 69 6e 33 32 00 57 69 6e 33 32 46 75 6e 63 74 69 6f 6e 73 00 6d 73 63 6f 72 6c 69 62 00 53 79 73 74 65 6d 00 4f 62 6a 65 63 74 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 43 72 65 61 74 65 54 68 72 65 61 64 00 2e 63 74 6f 72 00 6c 70 41 64 64 72 65 73 73 00 64 77 53 69 7a 65 00 66 6c 41 6c 6c 6f 63 61 74 69 6f 6e 54 79 70 65 00 66 6c 50 72 6f 74 65 63 74 00 6c}  //weight: 10, accuracy: High
        $x_10_2 = {2e 64 6c 6c 00 66 75 6e 63 00 69 6e 6a 65 63 74 00 41 6c 6c 6f 63 61 74 69 6f 6e 54 79 70 65 00 4d 65 6d 6f 72 79 50 72 6f 74 65 63 74 69 6f 6e 00 54 69 6d 65 00 6d 73 63 6f 72 6c 69 62 00 53 79 73 74 65 6d 00 4f 62 6a 65 63 74 00 45 6e 75 6d 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 43 72 65 61 74 65 54 68 72 65 61 64}  //weight: 10, accuracy: High
        $x_8_3 = {2e 64 6c 6c 00 57 69 6e 33 32 00 6d 73 63 6f 72 6c 69 62 00 53 79 73 74 65 6d 00 4f 62 6a 65 63 74 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 43 72 65 61 74 65 54 68 72 65 61 64}  //weight: 8, accuracy: High
        $x_8_4 = {6d 73 63 6f 72 6c 69 62 00 53 79 73 74 65 6d 00 4f 62 6a 65 63 74 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 43 72 65 61 74 65 54 68 72 65 61 64 00 1e 00 [0-4] 2e 64 6c 6c [0-12] 57 69 6e 33 32 46 75 6e 63 74 69 6f 6e 73 00}  //weight: 8, accuracy: Low
        $x_2_5 = {6c 70 41 64 64 72 65 73 73 00 64 77 53 69 7a 65 00 66 6c 41 6c 6c 6f 63 61 74 69 6f 6e 54 79 70 65 00 66 6c 50 72 6f 74 65 63 74 00 6c 70 54 68 72 65 61 64 41 74 74 72 69 62 75 74 65 73 00 64 77 53 74 61 63 6b 53 69 7a 65 00 6c 70 53 74 61 72 74 41 64 64 72 65 73 73 00 6c 70 50 61 72 61 6d 65 74 65 72 00 64 77 43 72 65 61 74 69 6f 6e 46 6c 61 67 73 00 6c 70 54 68 72 65 61 64 49 64}  //weight: 2, accuracy: High
        $x_2_6 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 00 44 6c 6c 49 6d 70 6f 72 74 41 74 74 72 69 62 75 74 65 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 6d 73 76 63 72 74 2e 64 6c 6c 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((2 of ($x_8_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Rozena_JSAA_2147906611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.JSAA!MTB"
        threat_id = "2147906611"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 7e ?? 00 00 0a 11 07 8e 69 20 00 10 00 00 1f 40 28 ?? 00 00 06 13 08 11 07 16 11 08 11 07 8e 69 28 ?? 00 00 0a 11 08 11 07 8e 69 1f 20 12 09 28 ?? 00 00 06 26 7e ?? 00 00 0a 26 16 13 0a 7e ?? 00 00 0a 16 11 08 7e ?? 00 00 0a 16 12 0a 28 ?? 00 00 06 15 28 ?? 00 00 06 26 de 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_HNE_2147907538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.HNE!MTB"
        threat_id = "2147907538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6d 73 63 6f 72 6c 69 62 00 53 79 73 74 65 6d 00 4f 62 6a 65 63 74 00 63 61 6c 6c 6f 63 00 43 72 65 61 74 65 54 68 72 65 61 64 00 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74}  //weight: 5, accuracy: High
        $x_1_2 = {00 64 77 43 72 65 61 74 69 6f 6e 46 6c 61 67 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 6c 70 54 68 72 65 61 64 49 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 66 6c 4e 65 77 50 72 6f 74 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 6c 70 53 74 61 72 74 41 64 64 72 65 73 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_HNF_2147907920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.HNF!MTB"
        threat_id = "2147907920"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 70 53 74 61 72 74 41 64 64 72 00 73 69 7a 65 00 66 6c 41 6c 6c 6f 63 61 74 69 6f 6e 54 79 70 65 00 66 6c 50 72 6f 74 65 63 74 00 6c 70 54 68 72 65 61 64 41 74 74 72 69 62 75 74 65 73 00 64 77 53 74 61 63 6b 53 69 7a 65 00 6c 70 53 74 61 72 74 41 64 64 72 65 73 73}  //weight: 1, accuracy: High
        $x_1_2 = {00 6c 70 54 68 72 65 61 64 41 74 74 72 69 62 75 74 65 73 00 64 77 43 72 65 61 74 69 6f 6e 46 6c 61 67 73 00 61 72 67 73 00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 6c 70 41 64 64 72 65 73 73 00 6c 70 53 74 61 72 74 41 64 64 72 65 73 73}  //weight: 1, accuracy: High
        $x_1_3 = {00 50 41 47 45 5f 45 58 45 43 55 54 45 5f 52 45 41 44 57 52 49 54 45 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 4d 45 4d 5f 43 4f 4d 4d 49 54 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_Rozena_HNG_2147908587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.HNG!MTB"
        threat_id = "2147908587"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 45 00 78 00 00 25 57 00 72 00 69 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 00 23 52 00 65 00 61 00 64 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 00 0b 6e 00 74 00 64 00 6c 00 6c 00 00 29 5a 00 77 00 55 00 6e 00 6d 00 61 00 70 00 56 00 69 00 65 00 77 00 4f 00 66 00 53 00 65 00 63 00 74 00 69 00 6f 00 6e 00 00 1d 43 00 72 00 65 00 61 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_N_2147908736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.N!MTB"
        threat_id = "2147908736"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 16 06 09 16 12 02 28 ?? 00 00 06 0b 16}  //weight: 5, accuracy: Low
        $x_1_2 = "Spotifys.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_RP_2147915841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.RP!MTB"
        threat_id = "2147915841"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 11 0a 08 11 0a 91 11 04 11 0a 1f 20 5d 91 61 d2 9c 08 11 0a 08 11 0a 91 09 11 0a 1f 20 5d 91 61 d2 9c 11 0a 13 0b 11 0b 17 58 13 0a 11 0a 08 8e 69 32 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NK_2147917955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NK!MTB"
        threat_id = "2147917955"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {11 04 09 28 15 00 00 0a 7e 14 00 00 0a 16 11 04 7e 14 00 00 0a 16 7e 14 00 00 0a 28 02 00 00 06 15}  //weight: 3, accuracy: High
        $x_1_2 = "av_bypass.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NL_2147917957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NL!MTB"
        threat_id = "2147917957"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {7e 14 00 00 0a 16 11 04 7e 14 00 00 0a 16 7e 14 00 00 0a 28 02 00 00 06 15}  //weight: 3, accuracy: High
        $x_2_2 = {0a 20 d0 07 00 00 28 04 00 00 06 28 10 00 00 0a 13 05 12 05 06 28 11 00 00 0a 13 06 12 06 28 12 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NL_2147917957_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NL!MTB"
        threat_id = "2147917957"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {06 72 19 00 00 70 72 85 00 00 70 6f 12 00 00 0a 00 06 72 20 01 00 70 72 94 01 00 70 6f 12 00 00 0a 00 00}  //weight: 3, accuracy: High
        $x_1_2 = "$ad4e3dd4-3a9b-4db7-a181-50c6e63eecb3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NA_2147918311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NA!MTB"
        threat_id = "2147918311"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 00 70 6f ?? 00 00 0a 0c 07 8e 69 8d ?? 00 00 01 0d 16 13 06 2b 18 09 11 06 07 11 06 91 08 11 06 08 8e 69 5d 91 61 d2 9c 11 06 17 58 13 06 11 06 07 8e 69 32 e1}  //weight: 3, accuracy: Low
        $x_2_2 = {01 13 07 11 06 11 07 16 11 07 8e 69 6f ?? 00 00 0a 26 09 11 07 28 ?? 00 00 0a de 1b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_KAH_2147918659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.KAH!MTB"
        threat_id = "2147918659"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 11 15 06 11 15 91 20 ?? 00 00 00 61 d2 9c 11 15 17 58 13 15 11 15 06 8e 69}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_KAU_2147919515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.KAU!MTB"
        threat_id = "2147919515"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 11 15 06 11 15 91 1f 1a 61 d2 9c 11 15 17 58 13 15 11 15 06 8e 69}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_KAF_2147919568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.KAF!MTB"
        threat_id = "2147919568"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 08 07 11 08 91 20 ?? 00 00 00 61 d2 9c 11 08 17 58 13 08 11 08 07 8e 69}  //weight: 5, accuracy: Low
        $x_1_2 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_KAG_2147919569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.KAG!MTB"
        threat_id = "2147919569"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 07 02 07 91 03 61 d2 9c 07 17 58 0b 07 02 8e 69 32 ed}  //weight: 5, accuracy: High
        $x_1_2 = "XORDecrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NN_2147920282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NN!MTB"
        threat_id = "2147920282"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {09 05 6f 14 00 00 0a 13 04 11 04 08 0e 05 6f ?? 00 00 0a 0a 06 13 06 2b 00 11 06 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "SneakyExec-master" ascii //weight: 1
        $x_1_3 = "$612590aa-af68-41e6-8ce2-e831f7fe4ccc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPAN_2147920486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPAN!MTB"
        threat_id = "2147920486"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 06 6f ?? ?? ?? 0a 0c 16 08 8e 69 20 00 10 00 00 1f 40 28 ?? ?? ?? 06 0d 16 13 04 08 16 09 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SHPF_2147920488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SHPF!MTB"
        threat_id = "2147920488"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 8e 69 0c 7e ?? ?? ?? 0a 08 20 00 30 00 00 1f 40 28 ?? ?? ?? 06 0d 16 13 06 2b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPRA_2147921752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPRA!MTB"
        threat_id = "2147921752"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 1d 59 0d 07 11 0a 91 13 0b 11 0b 11 05 61 13 0c 11 04 09 58 13 04 07 11 0a 11 0c d2 9c 00 11 0a 17 58 13 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_KAI_2147921796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.KAI!MTB"
        threat_id = "2147921796"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 06 07 11 06 91 20 ?? 00 00 00 61 d2 9c 11 06 17 58 13 06 11 06 07 8e 69 32 e4}  //weight: 5, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NE_2147923055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NE!MTB"
        threat_id = "2147923055"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {13 04 09 11 04 09 6f 20 00 00 0a 1e 5b 6f 21 00 00 0a 6f 22 00 00 0a 00 09 11 04 09 6f 23 00 00 0a 1e 5b 6f 21 00 00 0a}  //weight: 3, accuracy: High
        $x_2_2 = {0c 02 07 28 ?? 00 00 2b 28 ?? 00 00 06 00 02 28 ?? 00 00 06 0d 09 2c 11}  //weight: 2, accuracy: Low
        $x_1_3 = "AES_encrypt.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NG_2147923056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NG!MTB"
        threat_id = "2147923056"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {16 0a 7e 13 00 00 0a 0b 72 01 00 00 70 28 05 00 00 06 0c 08 8e 69 28 06 00 00 06 0d 08 09 28 07 00 00 06 00 09 12 00 28 08 00 00 06 0b 07}  //weight: 3, accuracy: High
        $x_1_2 = "dllmethod.g.resources" ascii //weight: 1
        $x_1_3 = "ShellcodeExecutor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SMDA_2147923088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SMDA!MTB"
        threat_id = "2147923088"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {11 05 11 06 11 05 11 06 91 1f 7a 61 d2 9c 11 06 17 58 13 06 11 06 11 05 8e 69 3f e1 ff ff ff}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SPDT_2147924277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SPDT!MTB"
        threat_id = "2147924277"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 06 8e 69 0b 7e ?? ?? ?? 0a 07 20 00 10 00 00 1f 40 28 ?? ?? ?? 06 0c 06 16 08 07}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SBDF_2147924278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SBDF!MTB"
        threat_id = "2147924278"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0d 16 09 8e 69 7e 01 00 00 04 7e 02 00 00 04 28 ?? 00 00 06 13 04 09 16 11 04 6e 28 ?? 00 00 0a 09 8e 69}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NT_2147924507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NT!MTB"
        threat_id = "2147924507"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {6f 12 00 00 0a 13 04 06 28 13 00 00 0a 73 14 00 00 0a 13 09 11 09 11 04 16 73 15 00 00 0a 13 0a 73 16 00 00 0a 13 0b 11 0a 11 0b 6f 17 00 00 0a 11 0b 6f 18 00 00 0a 13 05 de 24}  //weight: 3, accuracy: High
        $x_2_2 = {11 06 11 05 8e 69 1f 20 12 07 28 02 00 00 06 26 16 13 08 16 16 11 06 7e 1a 00 00 0a 16 12 08 28 03 00 00 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SCXF_2147927416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SCXF!MTB"
        threat_id = "2147927416"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {07 11 06 94 0d 08 09 06 11 06 91 9c 11 06 17 58 13 06 11 06 07 8e 69 32 e7}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_GNT_2147932095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.GNT!MTB"
        threat_id = "2147932095"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {26 16 13 08 16 16 11 06 7e ?? ?? ?? ?? 16 12 08 28}  //weight: 5, accuracy: Low
        $x_5_2 = {11 05 8e 69 20 00 10 00 00 1a 28 ?? ?? ?? 06 13 06 11 05 16 11 06 11 05 8e 69 28}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_NIT_2147932227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.NIT!MTB"
        threat_id = "2147932227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 05 00 00 06 0a 06 16 28 06 00 00 06 26 [0-5] 28 08 00 00 06 0b 07 28 09 00 00 06 2a}  //weight: 2, accuracy: Low
        $x_1_2 = {7e 03 00 00 04 2d 11 14 fe 06 0a 00 00 06 73 02 00 00 0a 80 03 00 00 04 7e 03 00 00 04 28 ?? 00 00 0a 74 02 00 00 01 28 ?? 00 00 0a 73 05 00 00 0a 0a 06 02 6f ?? 00 00 0a 0b 07 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SVJI_2147932397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SVJI!MTB"
        threat_id = "2147932397"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 8e 69 20 00 10 00 00 1a 28 ?? 00 00 06 0a 20 30 75 00 00 28 ?? 00 00 0a 02 16 06 02 8e 69 28 ?? 00 00 0a 20 30 75 00 00 28 ?? 00 00 0a 06 02 8e 69 20 00 10 00 00 1f 20}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_CCJR_2147934174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.CCJR!MTB"
        threat_id = "2147934174"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "[DllImport(\"kernel32.dll\")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect)" ascii //weight: 2
        $x_2_2 = "[DllImport(\"kernel32.dll\")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId)" ascii //weight: 2
        $x_1_3 = {30 00 78 00 31 00 30 00 30 00 30 00 3b 00 69 00 66 00 20 00 28 00 24 00 [0-15] 2e 00 4c 00 65 00 6e 00 67 00 74 00 68 00 20 00 2d 00 67 00 74 00 20 00 30 00 78 00 31 00 30 00 30 00 30 00 29 00 7b 00 24 00 [0-15] 20 00 3d 00 20 00 24 00 [0-15] 2e 00 4c 00 65 00 6e 00 67 00 74 00 68 00 7d 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_4 = {30 78 31 30 30 30 3b 69 66 20 28 24 [0-15] 2e 4c 65 6e 67 74 68 20 2d 67 74 20 30 78 31 30 30 30 29 7b 24 [0-15] 20 3d 20 24 [0-15] 2e 4c 65 6e 67 74 68 7d 3b}  //weight: 1, accuracy: Low
        $x_1_5 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 28 00 30 00 2c 00 30 00 78 00 31 00 30 00 30 00 30 00 2c 00 24 00 [0-15] 2c 00 30 00 78 00 34 00 30 00 29 00 3b 00 66 00 6f 00 72 00 20 00 28 00 24 00 69 00 3d 00 30 00 3b 00 24 00 69 00 20 00 2d 00 6c 00 65 00 20 00 28 00 24 00 [0-15] 2e 00 4c 00 65 00 6e 00 67 00 74 00 68 00 2d 00 31 00 29 00 3b 00 24 00 69 00 2b 00 2b 00 29 00 20 00 7b 00 24 00 77 00 3a 00 3a 00 6d 00 65 00 6d 00 73 00 65 00 74 00 28 00 5b 00 49 00 6e 00 74 00 50 00 74 00 72 00 5d 00 28 00 24 00 [0-15] 2e 00 54 00 6f 00 49 00 6e 00 74 00 33 00 32 00 28 00 29 00 2b 00 24 00 69 00 29 00 2c 00 20 00 24 00 [0-15] 5b 00 24 00 69 00 5d 00 2c 00 20 00 31 00 29 00 7d 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 28 30 2c 30 78 31 30 30 30 2c 24 [0-15] 2c 30 78 34 30 29 3b 66 6f 72 20 28 24 69 3d 30 3b 24 69 20 2d 6c 65 20 28 24 [0-15] 2e 4c 65 6e 67 74 68 2d 31 29 3b 24 69 2b 2b 29 20 7b 24 77 3a 3a 6d 65 6d 73 65 74 28 5b 49 6e 74 50 74 72 5d 28 24 [0-15] 2e 54 6f 49 6e 74 33 32 28 29 2b 24 69 29 2c 20 24 [0-15] 5b 24 69 5d 2c 20 31 29 7d 3b}  //weight: 1, accuracy: Low
        $x_1_7 = {43 00 72 00 65 00 61 00 74 00 65 00 54 00 68 00 72 00 65 00 61 00 64 00 28 00 30 00 2c 00 30 00 2c 00 24 00 [0-15] 2c 00 30 00 2c 00 30 00 2c 00 30 00 29 00 3b 00 66 00 6f 00 72 00 20 00 28 00 3b 00 3b 00 29 00 7b 00 53 00 74 00 61 00 72 00 74 00 2d 00 73 00 6c 00 65 00 65 00 70 00 20 00 36 00 30 00 7d 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_8 = {43 72 65 61 74 65 54 68 72 65 61 64 28 30 2c 30 2c 24 [0-15] 2c 30 2c 30 2c 30 29 3b 66 6f 72 20 28 3b 3b 29 7b 53 74 61 72 74 2d 73 6c 65 65 70 20 36 30 7d 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Rozena_EAJ_2147941306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.EAJ!MTB"
        threat_id = "2147941306"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 02 07 02 8e 69 5d 91 58 06 07 91 58 20 ff 00 00 00 5f 0c 06 07 08 28 04 00 00 06 07 17 58 0b 07 20 00 01 00 00 32 d8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_GAF_2147945455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.GAF!MTB"
        threat_id = "2147945455"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 61 d2 13 0a 11 0a 18 59 20 ff 00 00 00 5f d2 13 0a 07 11 09 11 0a 9c 11 09 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_ECM_2147946271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.ECM!MTB"
        threat_id = "2147946271"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 09 06 09 91 18 59 20 ff 00 00 00 5f d2 9c 09 17 58 0d 09 06 8e 69 32 e7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rozena_SLDA_2147951300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rozena.SLDA!MTB"
        threat_id = "2147951300"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 17 00 00 04 28 27 00 00 06 28 01 00 00 06 0a 06 20 3a 0b 11 8c 28 03 00 00 06 28 05 00 00 2b 80 02 00 00 04 06 20 d4 c3 b2 a1 28 03 00 00 06 28 06 00 00 2b 80 03 00 00 04 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

