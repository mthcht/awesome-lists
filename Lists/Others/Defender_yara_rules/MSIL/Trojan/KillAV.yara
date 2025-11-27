rule Trojan_MSIL_KillAV_NA_2147926692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KillAV.NA!MTB"
        threat_id = "2147926692"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {07 09 8e 69 09 16 7e 28 00 00 0a 16 7e 28 00 00 0a 28 04 00 00 06 2c 08 07 28 07 00 00 06}  //weight: 3, accuracy: High
        $x_2_2 = {8d 07 00 00 02 13 06 07 12 04 12 05 11 06 12 07 28 05 00 00 06 26 07 17 7e 28 00 00 0a 28 06 00 00 06 26 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KillAV_H_2147958354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KillAV.H!AMTB"
        threat_id = "2147958354"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KillAV"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {07 08 06 08 91 7e ?? 00 00 04 08 20 ff 00 00 00 5d 58 61 d2 9c 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d dd}  //weight: 3, accuracy: Low
        $x_2_2 = "DefenderBypass.exe" ascii //weight: 2
        $x_1_3 = "CRQaCQkeMiQ+MwsJDwQBDBk3IQQNHR8CHRUAKSEeFh0VDA9dOhrm5Ozn4ffawvDq5v7/5OHh483X6+Dw+OTx9vTo" ascii //weight: 1
        $x_1_4 = "dD4kOA==" ascii //weight: 1
        $x_1_5 = "CT4ocBMvMBMHBQEXAwkLDEpGKgIcDBU=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

