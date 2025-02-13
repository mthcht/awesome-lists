rule Backdoor_MSIL_NanoCoreRAT_A_2147835955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NanoCoreRAT.A!MTB"
        threat_id = "2147835955"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCoreRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 0b 07 6f ?? 00 00 0a 17 da 0c 16 0d 2b ?? 7e ?? 00 00 04 07 09 16 6f ?? 00 00 0a 13 ?? 12 ?? 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 17 d6 0d 09 08 31}  //weight: 1, accuracy: Low
        $x_1_2 = "ToArray" ascii //weight: 1
        $x_1_3 = "FromStream" ascii //weight: 1
        $x_1_4 = "Sleep" ascii //weight: 1
        $x_1_5 = "ToCharArray" ascii //weight: 1
        $x_1_6 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_7 = "GetManifestResourceStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_NanoCoreRAT_B_2147835968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NanoCoreRAT.B!MTB"
        threat_id = "2147835968"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCoreRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 14 72 32 50 02 70 18 8d 17 00 00 01 25 16 72 42 50 02 70 a2 25 17 72 48 50 02 70 a2 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 07 28 ?? 00 00 06 28 ?? 00 00 0a 0c 28 ?? 00 00 0a 14 72}  //weight: 2, accuracy: Low
        $x_1_2 = "GetExportedTypes" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_NanoCoreRAT_C_2147835970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NanoCoreRAT.C!MTB"
        threat_id = "2147835970"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCoreRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 07 02 07 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 1a}  //weight: 2, accuracy: Low
        $x_1_2 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_NanoCoreRAT_D_2147835972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NanoCoreRAT.D!MTB"
        threat_id = "2147835972"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCoreRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1f 2d 9d 6f 1c 00 28 ?? 00 00 06 72 ?? 03 00 70 72 ?? 03 00 70 6f ?? 00 00 0a 17 8d ?? 00 00 01 25 16}  //weight: 2, accuracy: Low
        $x_2_2 = {11 06 9a 1f 10 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
        $x_2_3 = {1f 25 9d 6f ?? 00 00 0a 13 04 09 00 04 17 8d ?? 00 00 01 25 16}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_NanoCoreRAT_E_2147836286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NanoCoreRAT.E!MTB"
        threat_id = "2147836286"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCoreRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 25 16 1f 40 9d 6f 04 00 0a 17 8d}  //weight: 2, accuracy: Low
        $x_2_2 = {07 06 11 08 9a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09}  //weight: 2, accuracy: Low
        $x_2_3 = {00 00 01 25 16 1f 25 9d 6f 04 00 04 17 8d}  //weight: 2, accuracy: Low
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "GetMethods" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_NanoCoreRAT_G_2147846837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NanoCoreRAT.G!MTB"
        threat_id = "2147846837"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCoreRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 25 16 20 ?? ?? ?? 00 28 ?? ?? 00 06 a2 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 01 38}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 01 25 16 20 ?? ?? ?? 00 28 ?? ?? 00 06 a2 25 17 20 ?? ?? ?? 00 28 ?? ?? 00 06 a2 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 01 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

