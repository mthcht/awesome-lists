rule Ransom_MSIL_Cobra_PA_2147767321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cobra.PA!MTB"
        threat_id = "2147767321"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ransomware" ascii //weight: 1
        $x_1_2 = {59 00 6f 00 75 00 20 00 68 00 61 00 76 00 65 00 20 00 [0-48] 20 00 76 00 69 00 63 00 74 00 69 00 6d 00 20 00 [0-48] 20 00 72 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 00 6f 00 62 00 72 00 61 00 5f 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 [0-16] 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00}  //weight: 1, accuracy: Low
        $x_1_4 = "your important files are encrypted!" wide //weight: 1
        $x_1_5 = "Your copmuter has been locked by BlackMamba 2.0 Ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Cobra_PC_2147772458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cobra.PC!MTB"
        threat_id = "2147772458"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "All your important files are encrypted!" ascii //weight: 1
        $x_1_2 = "Cobra_Locker" ascii //weight: 1
        $x_1_3 = "Start_Encrypt" ascii //weight: 1
        $x_1_4 = {5c 43 6f 62 72 61 5f 4c 6f 63 6b 65 72 5c 43 6f 62 72 61 5f 4c 6f 63 6b 65 72 5c [0-32] 5c 43 6f 62 72 61 5f 4c 6f 63 6b 65 72 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cobra_PD_2147784853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cobra.PD!MTB"
        threat_id = "2147784853"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Cobra" ascii //weight: 1
        $x_1_2 = "Cobra_Locker@" ascii //weight: 1
        $x_1_3 = "All your important files were encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

