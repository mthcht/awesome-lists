rule Ransom_MSIL_NominatusCrypto_PA_2147812993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/NominatusCrypto.PA!MTB"
        threat_id = "2147812993"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NominatusCrypto"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".exe >>autorun.inf" wide //weight: 1
        $x_1_2 = "vssadmin delete shadows /all /quiet && wmic shadowcopy delete" wide //weight: 1
        $x_1_3 = "taskkill /im wininit.exe /f" wide //weight: 1
        $x_1_4 = "\\EvilNominatusCrypto.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_NominatusCrypto_KSG_2147819895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/NominatusCrypto.KSG!MSR"
        threat_id = "2147819895"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NominatusCrypto"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EvilNominatus" wide //weight: 1
        $x_1_2 = "Your Files has been Encrypted" ascii //weight: 1
        $x_1_3 = "RozbehInvaders.pdb" ascii //weight: 1
        $x_1_4 = ".exe >>autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_NominatusCrypto_ABG_2147896629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/NominatusCrypto.ABG!MTB"
        threat_id = "2147896629"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NominatusCrypto"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encryptDirectory" ascii //weight: 1
        $x_1_2 = "GetFolderPath" ascii //weight: 1
        $x_1_3 = "GetDrives" ascii //weight: 1
        $x_1_4 = "EnterDebugMode" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "GetFiles" ascii //weight: 1
        $x_1_7 = "autorun.inf" wide //weight: 1
        $x_1_8 = "taskkill" wide //weight: 1
        $x_1_9 = "ROZBEH666a4e4133XORe2ea2315a1916" wide //weight: 1
        $x_1_10 = "NominatusCrypto" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

