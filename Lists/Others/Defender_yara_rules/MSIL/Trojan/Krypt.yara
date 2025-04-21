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
        $x_3_1 = "$command = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String" ascii //weight: 3
        $x_1_2 = "bmN0aW9uIFRlc3QtVk13YXJlIHsKICAgICR2bXdhcmVTZXJ2aWNlcyA9IEAoInZtZGVidWciLCAidm1tb3VzZSIsICJWTVRvb" ascii //weight: 1
        $x_1_3 = "2xzIiwgIlZNTUVNQ1RMIiwgInRwYXV0b2Nvbm5zdmMiLCAidHB2Y2dhdGV3YXkiLCAidm13YXJlIiwgIndtY2kiLCAidm14ODYiKQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

