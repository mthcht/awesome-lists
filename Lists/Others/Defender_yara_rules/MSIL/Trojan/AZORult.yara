rule Trojan_MSIL_Azorult_GN_2147760829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Azorult.GN!MTB"
        threat_id = "2147760829"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 12 01 28 ?? ?? ?? 0a 0a 02 7b ?? ?? ?? 04 02 7b ?? ?? ?? 04 02 7b ?? ?? ?? 04 02 7b ?? ?? ?? 04 91 06 02 7b ?? ?? ?? 04 06 8e 69 5d 91 61 d2 9c 02 25 7b ?? ?? ?? 04 17 58 7d ?? ?? ?? 04 02 7b ?? ?? ?? 04 02 7b ?? ?? ?? 04 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Azorult_MK_2147760962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Azorult.MK!MTB"
        threat_id = "2147760962"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RemotePropertyHolderAttribute!" ascii //weight: 1
        $x_1_2 = "StackBehaviour" ascii //weight: 1
        $x_1_3 = "IChannelReceiver" ascii //weight: 1
        $x_1_4 = "RemotingMethodCachedData in senso decrescente:" ascii //weight: 1
        $x_1_5 = "STORE_ASSEMBLY_FILE_STATUS_FLAGS STORE_ASSEMBLY_FILE_STATUS_FLAGS Asc:" ascii //weight: 1
        $x_1_6 = "Normalization Normalization Strano:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Azorult_PAF_2147777162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Azorult.PAF!MTB"
        threat_id = "2147777162"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "41\\:41\\:41\\:41\\:41\\:41\\:41\\" ascii //weight: 1
        $x_1_2 = "SecurityContextRunData.My" ascii //weight: 1
        $x_1_3 = "get_ResourceManager" ascii //weight: 1
        $x_1_4 = "get_txtPassword1" ascii //weight: 1
        $x_1_5 = "btn_Login1_Click" ascii //weight: 1
        $x_1_6 = "get_txtUsername1" ascii //weight: 1
        $x_1_7 = "get_WebServices" ascii //weight: 1
        $x_1_8 = "get_btn_Login1" ascii //weight: 1
        $x_1_9 = "get_LoginSPOC" ascii //weight: 1
        $x_1_10 = "_chkShowpass" ascii //weight: 1
        $x_1_11 = "m_LoginSPOC" ascii //weight: 1
        $x_1_12 = "MyComputer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Azorult_ABM_2147789557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Azorult.ABM!MTB"
        threat_id = "2147789557"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "!Host Process for Windows Services" ascii //weight: 3
        $x_3_2 = "Confuser.Core 1.6.0-alpha" ascii //weight: 3
        $x_3_3 = "BlockCopy" ascii //weight: 3
        $x_3_4 = "set_UseShellExecute" ascii //weight: 3
        $x_3_5 = "add_AssemblyResolve" ascii //weight: 3
        $x_3_6 = "FromBase64String" ascii //weight: 3
        $x_3_7 = "IsLittleEndian" ascii //weight: 3
        $x_3_8 = "CreateDecryptor" ascii //weight: 3
        $x_3_9 = "Rfc2898DeriveBytes" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_MSIL_Azorult_EC_2147831755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Azorult.EC!MTB"
        threat_id = "2147831755"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetDomain" ascii //weight: 1
        $x_1_2 = "GetTempPath" ascii //weight: 1
        $x_1_3 = "PatchComposer" ascii //weight: 1
        $x_1_4 = "crRcenhngcnnkn9dv" ascii //weight: 1
        $x_1_5 = "C:\\TEMP\\__empty" wide //weight: 1
        $x_1_6 = "Rcenhngcnnknydvzuareir" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Azorult_AZ_2147844092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Azorult.AZ!MTB"
        threat_id = "2147844092"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 10 2b 0d 00 11 10 11 11 d2 6f ?? ?? ?? 0a 00 00 11 0f 6f ?? ?? ?? 0a 25 13 11 15 fe 01 16 fe 01 13 12 11 12 2d dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Azorult_SPQ_2147845703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Azorult.SPQ!MTB"
        threat_id = "2147845703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {11 1e 11 20 18 6f ?? ?? ?? 0a 20 03 02 00 00 28 ?? ?? ?? 0a 13 22 11 1f 11 22 6f ?? ?? ?? 0a 00 11 20 18 58 13 20 00 11 20 11 1e 6f ?? ?? ?? 0a fe 04 13 23 11 23 2d c7}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Azorult_AKAA_2147900407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Azorult.AKAA!MTB"
        threat_id = "2147900407"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 05 09 11 05 09 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 09 11 05 09 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 09 17 6f ?? 00 00 0a 08 09 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 06 11 06 02 16 02 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a de 0c 11 06 2c 07 11 06 6f ?? 00 00 0a dc 08 6f ?? 00 00 0a 0a de 0a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Azorult_GMZ_2147900600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Azorult.GMZ!MTB"
        threat_id = "2147900600"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 0a 14 17 8d 01 00 00 01 25 16 28 ?? ?? ?? 06 a2 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 2b 06 0a 2b b4 0b 2b ba 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Azorult_MA_2147901640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Azorult.MA!MTB"
        threat_id = "2147901640"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DisableTaskMgr" wide //weight: 1
        $x_1_2 = "DisableRealtimeMonitoring" wide //weight: 1
        $x_1_3 = "DownloadFile" ascii //weight: 1
        $x_1_4 = "gojekpromo.com" wide //weight: 1
        $x_1_5 = "MemoryStream" ascii //weight: 1
        $x_1_6 = "GZipStream" ascii //weight: 1
        $x_1_7 = "RegistryKeyPermissionCheck" ascii //weight: 1
        $x_1_8 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Azorult_GNK_2147917054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Azorult.GNK!MTB"
        threat_id = "2147917054"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 20 11 1f 11 21 6f ?? ?? ?? 0a 11 1d 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 26 11 21 17 58 13 21 11 21 11 1f 6f ?? ?? ?? 0a fe 04 13 22 11 22 2d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Azorult_KAA_2147919182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Azorult.KAA!MTB"
        threat_id = "2147919182"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 08 91 0d 09 08 59 20 ff 00 00 00 5f 0d 09 03 1e 5d 1f 1f 5f 63 09 1e 03 1e 5d 59 1f 1f 5f 62 60 20 ff 00 00 00 5f 0d 09 03 59 20 ff 00 00 00 5f 0d 09 03 61 0d 06 08 09 d2 9c 00 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

