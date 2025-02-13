rule Ransom_MSIL_DeathShadow_PA_2147762257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/DeathShadow.PA!MTB"
        threat_id = "2147762257"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DeathShadow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<EncryptFile>b__0" ascii //weight: 1
        $x_1_2 = {5c 44 65 61 74 68 5f 53 68 61 64 6f 77 5c 62 69 6e 5c [0-16] 5c 53 65 63 75 72 65 64 5c 44 65 61 74 68 5f 53 68 61 64 6f 77 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = "Death_Shadow.exe" wide //weight: 1
        $x_1_4 = "AgileDotNetRT64" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

