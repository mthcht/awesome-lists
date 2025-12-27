rule Trojan_MSIL_Krypt_PGK_2147937928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Krypt.PGK!MTB"
        threat_id = "2147937928"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Krypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {25 4a 09 61 54 09 17 62 09 1d 63 60 0d 00 11 09 17 58 13 09 11 09 06 8e 69 fe 04 13 0a 11 0a 2d d6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Krypt_PGK_2147937928_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Krypt.PGK!MTB"
        threat_id = "2147937928"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Krypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 05 11 08 07 06 11 08 58 93 11 06 11 08 08 58 11 07 5d 93 61 d1 9d 17 11 08 58 13 08 11 08 11 04 fe 04 2d db}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Krypt_PGK_2147937928_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Krypt.PGK!MTB"
        threat_id = "2147937928"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Krypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "TkVRMVFUa3dNREF3TXpBd01EQXdNREEwTURBd01EQXdSa1pH" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Krypt_PGK_2147937928_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Krypt.PGK!MTB"
        threat_id = "2147937928"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Krypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "VFhwTmVrNUVUVEJOZWxGNlRYcE5NVTE2VVhwTlZFMTZUWHBy" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Krypt_PGK_2147937928_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Krypt.PGK!MTB"
        threat_id = "2147937928"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Krypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "$command = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String" ascii //weight: 3
        $x_1_2 = "bmN0aW9uIFRlc3QtVk13YXJlIHsKICAgICR2bXdhcmVTZXJ2aWNlcyA9IEAoInZtZGVidWciLCAidm1tb3VzZSIsICJWTVRvb" ascii //weight: 1
        $x_1_3 = "2xzIiwgIlZNTUVNQ1RMIiwgInRwYXV0b2Nvbm5zdmMiLCAidHB2Y2dhdGV3YXkiLCAidm13YXJlIiwgIndtY2kiLCAidm14ODYiKQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Krypt_PSS_2147951169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Krypt.PSS!MTB"
        threat_id = "2147951169"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Krypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {11 10 6f c0 00 00 0a 13 11 08 28 ?? ?? ?? 0a 2d 10 08 11 11 28 ?? ?? ?? 0a 16 13 1e dd ?? ?? ?? 00 11 0a 2c 74 11 18 7b ?? ?? ?? 04 1f 09 8d ?? ?? ?? 01 13 23 11 23 16 72 c0 03 00 70 a2 11 23 17}  //weight: 7, accuracy: Low
        $x_2_2 = {44 6f 6e 27 74 20 6c 6f 6f 6b 20 61 74 20 74 68 69 73 2e 2e 2e 0d 0a 24 49 6d 61 67 65 20 3d 20 22 41 41 41 42 41 41 45 41 67 49 41 41 41 41 45 41 49 41 41 6f 43 41 45 41 46 67 41 41 41 43 67 41 41 41 43 41 41 41 41 41 41 41 45 41 41 41 45 41 49 41 41 41 41 41 41 41 41 41 41 42 41 49 63 64 41 41 43 48 48 51 41 41 41 41 41 41 41 41 41 41 41 41 44 2f 2f}  //weight: 2, accuracy: High
        $x_1_3 = "Set-Content $batFile \"schtasks /run /TN $taskName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

