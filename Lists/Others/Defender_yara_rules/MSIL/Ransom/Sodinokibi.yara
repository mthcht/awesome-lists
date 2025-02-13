rule Ransom_MSIL_Sodinokibi_MA_2147817322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Sodinokibi.MA!MTB"
        threat_id = "2147817322"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sodinokibi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PenterWare.exe" wide //weight: 1
        $x_1_2 = ".PNT-RNSM" wide //weight: 1
        $x_1_3 = "Contents of shadow copy set ID" wide //weight: 1
        $x_1_4 = "HKCU\\SOFTWARE\\recfg\\sk_key" ascii //weight: 1
        $x_1_5 = "HKLM\\SOFTWARE\\recfg\\pk_key" ascii //weight: 1
        $x_1_6 = "HKLM\\SOFTWARE\\recfg\\stat" ascii //weight: 1
        $x_1_7 = "SelfDestruct" ascii //weight: 1
        $x_1_8 = "echo j | del /F" wide //weight: 1
        $x_1_9 = "Base64Decode" ascii //weight: 1
        $x_1_10 = "GetBytes" ascii //weight: 1
        $x_1_11 = "SetMaxBytesForEncryption" ascii //weight: 1
        $x_1_12 = "Executing hidden command" wide //weight: 1
        $x_1_13 = "ForceCopyFile" ascii //weight: 1
        $x_1_14 = "FastEncryptionMaxBytes" ascii //weight: 1
        $x_1_15 = "DecryptFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

