rule Trojan_MSIL_ZillaCrypt_NG_2147926320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZillaCrypt.NG!MTB"
        threat_id = "2147926320"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZillaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {58 11 07 59 17 5b 6a 69 0c 2b 19 07 03 17}  //weight: 2, accuracy: High
        $x_1_2 = {00 08 16 32 14 09 16 32 10 09 08 31 0c 08 11 04 8e 69 fe 04 16 fe 01 2b 01}  //weight: 1, accuracy: High
        $x_1_3 = "94B35817-E9CA-477A-9F42-1A2184D47F00" ascii //weight: 1
        $x_1_4 = "TeZFfjD34A7jvG75o6Nq9C9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZillaCrypt_NMA_2147935689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZillaCrypt.NMA!MTB"
        threat_id = "2147935689"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZillaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "8e390499-23f7-49c0-9adf-43dedcab9b92" ascii //weight: 2
        $x_2_2 = {11 31 11 0e 46 11 21 61 52 11 0e 17 58 13 0e 11 31 17 58 13 31 2b e2}  //weight: 2, accuracy: High
        $x_1_3 = {e0 4a 11 08 11 11 17 59 8f c3 00 00 01 e0 4a 61 54 11 0f 11 11 18 59 16}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

