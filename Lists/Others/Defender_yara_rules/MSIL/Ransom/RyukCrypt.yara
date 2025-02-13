rule Ransom_MSIL_RyukCrypt_PC_2147782525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/RyukCrypt.PC!MTB"
        threat_id = "2147782525"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RyukCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Read_it.txt" wide //weight: 1
        $x_1_2 = "#encryptedFileExtension" wide //weight: 1
        $x_1_3 = "Ryuk Ransomware" wide //weight: 1
        $x_1_4 = "/target:winexe /platform:anycpu /optimize+" wide //weight: 1
        $x_1_5 = "\\Ryuk .Net Ransomware Builder.pdb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_RyukCrypt_PE_2147782788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/RyukCrypt.PE!MTB"
        threat_id = "2147782788"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RyukCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "appMutexRun" ascii //weight: 1
        $x_1_2 = "<EncyptedKey>" ascii //weight: 1
        $x_1_3 = "\\read_it.txt" ascii //weight: 1
        $x_1_4 = "ransomware virus" ascii //weight: 1
        $x_1_5 = "All of your files have been encrypted" ascii //weight: 1
        $x_1_6 = "ryuk.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_MSIL_RyukCrypt_PG_2147846929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/RyukCrypt.PG!MTB"
        threat_id = "2147846929"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RyukCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "appMutexRun" ascii //weight: 1
        $x_1_2 = "<EncyptedKey>" wide //weight: 1
        $x_1_3 = "\\read_it.txt" wide //weight: 1
        $x_1_4 = "You Have Been Hacked!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

