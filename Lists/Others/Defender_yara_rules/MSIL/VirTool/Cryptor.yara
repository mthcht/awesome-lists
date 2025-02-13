rule VirTool_MSIL_Cryptor_2147742484_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Cryptor!MTB"
        threat_id = "2147742484"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_B" ascii //weight: 1
        $x_1_2 = "get_G" ascii //weight: 1
        $x_1_3 = "get_R" ascii //weight: 1
        $x_1_4 = "MYSQL_CORE" ascii //weight: 1
        $x_1_5 = "Core_SQL" ascii //weight: 1
        $x_1_6 = "UpdateSQL" ascii //weight: 1
        $x_1_7 = "ClassSQL" ascii //weight: 1
        $x_1_8 = "ConnectMySQL" ascii //weight: 1
        $x_1_9 = "RetrySQL" ascii //weight: 1
        $x_10_10 = "CoreCodes.dll" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Cryptor_2147742484_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Cryptor!MTB"
        threat_id = "2147742484"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Module>" ascii //weight: 1
        $x_1_2 = "<PrivateImplementationDetails>" ascii //weight: 1
        $x_1_3 = "get_locked" ascii //weight: 1
        $x_1_4 = "set_locked" ascii //weight: 1
        $x_1_5 = "get_passWord" ascii //weight: 1
        $x_1_6 = "set_passWord" ascii //weight: 1
        $x_1_7 = "KoiVM" ascii //weight: 1
        $x_1_8 = "System.Threading" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "get_ConnectionString" ascii //weight: 1
        $x_1_11 = "GetFunctionPointer" ascii //weight: 1
        $x_1_12 = "set_UseVisualStyleBackColor" ascii //weight: 1
        $x_1_13 = "get_PowerPoint" ascii //weight: 1
        $x_1_14 = "GetResourceString" wide //weight: 1
        $x_1_15 = "SkipVerification" wide //weight: 1
        $x_1_16 = "#Koi" wide //weight: 1
        $x_1_17 = "In$J$ct0r" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

