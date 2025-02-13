rule Ransom_MSIL_Parasite_MK_2147773005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Parasite.MK!MTB"
        threat_id = "2147773005"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Parasite"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".betarasite" ascii //weight: 1
        $x_10_2 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 10
        $x_10_3 = "wbadmin delete catalog -quiet" ascii //weight: 10
        $x_10_4 = "All your files are encrypted" ascii //weight: 10
        $x_10_5 = "files have been encrypted using RC4 and RSA-2048" ascii //weight: 10
        $x_1_6 = "YOUR PERSONNAL SESSION ID:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Parasite_MK_2147773005_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Parasite.MK!MTB"
        threat_id = "2147773005"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Parasite"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".parasite" ascii //weight: 1
        $x_10_2 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 10
        $x_10_3 = "wbadmin delete catalog -quiet" ascii //weight: 10
        $x_10_4 = "Your ID is:" ascii //weight: 10
        $x_10_5 = "All your files are encrypted" ascii //weight: 10
        $x_10_6 = "All your files have been encrypted using RSA-2048 and RC4 encryption algorithm" ascii //weight: 10
        $x_1_7 = "@READ_ME_FILE_ENCRYPTED@.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

