rule Ransom_MSIL_Small_B_2147786310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Small.B!MTB"
        threat_id = "2147786310"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files are encrypted" ascii //weight: 1
        $x_1_2 = "extensionsToEncrypt" ascii //weight: 1
        $x_1_3 = "DirectoriesToEncrypt" ascii //weight: 1
        $x_1_4 = ".Xerog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Small_C_2147786657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Small.C!MTB"
        threat_id = "2147786657"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 1
        $x_1_3 = "encryptedFileExtension" ascii //weight: 1
        $x_1_4 = "EncyptedKey" ascii //weight: 1
        $x_1_5 = "read_it.txt" ascii //weight: 1
        $x_1_6 = "EncryptFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Small_D_2147788364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Small.D!MTB"
        threat_id = "2147788364"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted" ascii //weight: 1
        $x_1_2 = "File is already encrypted" ascii //weight: 1
        $x_1_3 = "RunSomeAware" ascii //weight: 1
        $x_1_4 = "Urgent Notice.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

