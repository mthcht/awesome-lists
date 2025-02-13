rule Ransom_MSIL_SharpCrypter_PA_2147772075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SharpCrypter.PA!MTB"
        threat_id = "2147772075"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SharpCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".0x0M4R" wide //weight: 1
        $x_1_2 = "Ransomware.Properties.Resources" wide //weight: 1
        $x_1_3 = "0x0M4R a malheureusement infect" ascii //weight: 1
        $x_1_4 = {5c 4f 50 53 49 45 5c 50 72 6f 6a 65 74 5f 52 61 6e 73 6f 6d 77 61 72 65 5f 63 73 68 61 72 70 5f 42 52 4f 43 41 52 44 5f 42 41 53 53 41 49 44 5f 42 45 4e 48 41 44 44 41 44 5c 52 61 6e 73 6f 6d 77 61 72 65 5c 52 61 6e 73 6f 6d 77 61 72 65 5c [0-48] 5c 41 64 6f 62 65 20 52 65 61 64 65 72 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

