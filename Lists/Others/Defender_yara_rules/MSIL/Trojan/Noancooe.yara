rule Trojan_MSIL_Noancooe_D_2147720453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noancooe.D!bit"
        threat_id = "2147720453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noancooe"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 00 63 00 20 00 65 00 63 00 68 00 6f 00 20 00 5b 00 7a 00 6f 00 6e 00 65 00 54 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 5d 00 5a 00 6f 00 6e 00 65 00 49 00 44 00 20 00 3d 00 20 00 32 00 20 00 ?? ?? 3a 00 5a 00 4f 00 4e 00 45 00 2e 00 69 00 64 00 65 00 6e 00 74 00 69 00 66 00 69 00 65 00 72 00 20 00 26 00 20 00 65 00 78 00 69 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 ?? ?? 2f 00 43 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 54 00 4e 00 20 00 22 00 55 00 70 00 64 00 61 00 74 00 65 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 ?? ?? 45 00 6e 00 61 00 62 00 6c 00 65 00 4c 00 55 00 41 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 ?? ?? 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 43 00 4d 00 44 00}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 ?? ?? 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00}  //weight: 1, accuracy: Low
        $x_1_6 = {73 00 62 00 69 00 65 00 64 00 6c 00 6c 00 ?? ?? 77 00 69 00 72 00 65 00 73 00 68 00 61 00 72 00 6b 00 ?? ?? 46 00 69 00 64 00 64 00 6c 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_7 = {77 00 69 00 72 00 65 00 73 00 68 00 61 00 72 00 6b 00 ?? ?? 46 00 69 00 64 00 64 00 6c 00 65 00 72 00 ?? ?? 57 00 50 00 45 00 20 00 50 00 52 00 4f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MSIL_Noancooe_AJ_2147741682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noancooe.AJ!MTB"
        threat_id = "2147741682"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noancooe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 04 00 00 06 28 01 00 00 0a 28 02 00 00 0a 6f 03 00 00 0a 14 14 6f 04 00 00 0a 26 16 28 05 00 00 0a dd 06 00 00 00 26 dd 00 00 00 00 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Noancooe_GEBBA_2147813204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noancooe.GEBBA!MTB"
        threat_id = "2147813204"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noancooe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2b 26 16 0b 07 45 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 00 00 0a 00 00 00 d0 02 00 00 06 26 19 0b 2b dc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

