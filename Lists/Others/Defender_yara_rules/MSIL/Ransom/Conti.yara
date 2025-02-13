rule Ransom_MSIL_Conti_STR_2147816511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Conti.STR!MTB"
        threat_id = "2147816511"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CONTI-Hiensiv_Ggydlela.png" ascii //weight: 1
        $x_1_2 = "MemoryStream" ascii //weight: 1
        $x_1_3 = "CopyTo" ascii //weight: 1
        $x_1_4 = "WebRequest" ascii //weight: 1
        $x_1_5 = "MoveNext" ascii //weight: 1
        $x_1_6 = "UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMgAwAA==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Conti_MA_2147821402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Conti.MA!MTB"
        threat_id = "2147821402"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EConti, HOW_TO_DECRYPTP, The system is LOCKED., The network is LOCKED." ascii //weight: 1
        $x_1_2 = "PenterWare" ascii //weight: 1
        $x_1_3 = "GetFreeSpaceMB" ascii //weight: 1
        $x_1_4 = "ForceCopyFile" ascii //weight: 1
        $x_1_5 = "ShredFile" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "EncryptedFiles" ascii //weight: 1
        $x_1_8 = "\\ProgramData\\PenterWare.txt" wide //weight: 1
        $x_1_9 = "echo j | del deleteMyProgram.bat" wide //weight: 1
        $x_1_10 = "DeleteShadowMode" wide //weight: 1
        $x_1_11 = "RansomNote.PNT-RNSM" wide //weight: 1
        $x_1_12 = "vssadmin.exe delete shadows /all /quiet /?" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

