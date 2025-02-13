rule Ransom_MSIL_ProtonCrypt_PAA_2147794907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/ProtonCrypt.PAA!MTB"
        threat_id = "2147794907"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ProtonCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncryptFile" ascii //weight: 1
        $x_1_2 = "GetComputerNameEx" ascii //weight: 1
        $x_1_3 = "bytesToBeEncrypted" ascii //weight: 1
        $x_1_4 = "ComputerNameNetBIOS" ascii //weight: 1
        $x_1_5 = "ComputerNamePhysicalNetBIOS" ascii //weight: 1
        $x_1_6 = "ComputerNamePhysicalDnsHostname" ascii //weight: 1
        $x_1_7 = "ProjectProton.proton.service.exe" ascii //weight: 1
        $x_1_8 = "WRITE 'proton' TO RUN RANSOMWARE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

