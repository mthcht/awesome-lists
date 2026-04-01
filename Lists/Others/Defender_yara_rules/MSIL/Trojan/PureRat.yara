rule Trojan_MSIL_PureRat_AB_2147963138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AB!MTB"
        threat_id = "2147963138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {38 a6 ff ff ff 00 11 11 11 00 6f ?? 00 00 0a 17 73 0b 00 00 0a 13 02 38 00 00 00 00 00 11 02 02 16 02 8e 69 6f ?? 00 00 0a 38 2e 00 00 00 38 09 00 00 00 20 00 00 00 00 fe 0e 0e 00 fe 0c 0e 00 45 01 00 00 00 4c 00 00 00 fe 0c 0e 00 20 dc 03 00 00 3b e5 ff ff ff 38 39 00 00 00 11 02 6f ?? 00 00 0a 38 00 00 00 00 11 11 6f ?? 00 00 0a 73 0f 00 00 0a 13 03 20 04 00 00 00 7e 4d 00 00 04 7b 47 00 00 04 3a b6 ff ff ff 26 20}  //weight: 6, accuracy: Low
        $x_2_2 = "FromBase64String" ascii //weight: 2
        $x_2_3 = "TripleDESCryptoServiceProvider" ascii //weight: 2
        $x_2_4 = "GZipStream" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureRat_AC_2147963631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AC!MTB"
        threat_id = "2147963631"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {11 02 11 00 6f ?? 00 00 0a 38 00 00 00 00 73 0c 00 00 0a 13 03 38 0e 00 00 00 11 02 11 0a 6f ?? 00 00 0a 38 d8 ff ff ff 00 11 03 11 02 6f ?? 00 00 0a 17 73 0f 00 00 0a 13 08 38 00 00 00 00 00 11 08 02 16 02 8e 69 6f ?? 00 00 0a 38 3c 00 00 00 38 09 00 00 00 20 00 00 00 00 fe 0e 04 00 fe 0c}  //weight: 6, accuracy: Low
        $x_2_2 = "FromBase64String" ascii //weight: 2
        $x_2_3 = "TripleDESCryptoServiceProvider" ascii //weight: 2
        $x_2_4 = "GZipStream" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureRat_AD_2147963725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AD!MTB"
        threat_id = "2147963725"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {38 00 00 00 00 11 02 11 00 6f ?? 00 00 0a 38 00 00 00 00 11 02 11 01 6f ?? 00 00 0a 38 00 00 00 00 11 02 6f ?? 00 00 0a 13 03 38 00 00 00 00 00 02 73 09 00 00 0a 13 0a 38 00 00 00 00 00 11 0a 11 03 16 73 17 00 00 0a 13 05 38 00 00 00 00 00 73 0a 00 00 0a 13 06 38 00 00 00 00 00 11 05 11 06 6f ?? 00 00 0a 38 00 00 00 00 11 06}  //weight: 6, accuracy: Low
        $x_2_2 = "FromBase64String" ascii //weight: 2
        $x_2_3 = "System.Reflection" ascii //weight: 2
        $x_2_4 = "GZipStream" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureRat_AE_2147965237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AE!MTB"
        threat_id = "2147965237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "<Module>{0b959ac9-c472-407b-870f-6b1a5d3e1db2}" ascii //weight: 2
        $x_2_2 = "ProtoBuf.Serializers.IProtoTypeSerializer.HasCallbacks" ascii //weight: 2
        $x_2_3 = "System.Reflection" ascii //weight: 2
        $x_2_4 = "PureHVNC_Lib.Networking" ascii //weight: 2
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "Microsoft.CodeAnalysis" ascii //weight: 1
        $x_1_7 = "WritePacked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureRat_AF_2147965240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AF!MTB"
        threat_id = "2147965240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "<Module>{09D611C0-FB7B-E958-B628-0ADDCF2E3E7D}" ascii //weight: 2
        $x_2_2 = "ProtoBuf.Serializers.IProtoTypeSerializer.HasCallbacks" ascii //weight: 2
        $x_2_3 = "System.Reflection" ascii //weight: 2
        $x_2_4 = "PureHVNC_Lib.Logging" ascii //weight: 2
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "Microsoft.CodeAnalysis" ascii //weight: 1
        $x_1_7 = "WritePacked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureRat_AG_2147965241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AG!MTB"
        threat_id = "2147965241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "System.Collections.Generic.IEnumerator<PureHVNC_Lib.Packets.FileManager.TransferPack>.get_Current" ascii //weight: 2
        $x_2_2 = "CreateDecryptor" ascii //weight: 2
        $x_2_3 = "GZipStream" ascii //weight: 2
        $x_2_4 = "System.Net.Sockets" ascii //weight: 2
        $x_2_5 = "ProtoBuf.Serializers.IProtoSerializer.Write" ascii //weight: 2
        $x_2_6 = "ProtoBuf.Serializers.IProtoTypeSerializer.HasCallbacks" ascii //weight: 2
        $x_2_7 = "FromBase64String" ascii //weight: 2
        $x_2_8 = "Microsoft.CodeAnalysis" ascii //weight: 2
        $x_2_9 = "WritePacked" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureRat_AH_2147965370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AH!MTB"
        threat_id = "2147965370"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {05 00 04 7b ?? 05 00 04 61 28 b1 0a 00 06 28}  //weight: 6, accuracy: Low
        $x_6_2 = {05 00 04 7b ?? 05 00 04 61 28 ab 0a 00 06 20}  //weight: 6, accuracy: Low
        $x_2_3 = "CreateDecryptor" ascii //weight: 2
        $x_2_4 = "GZipStream" ascii //weight: 2
        $x_2_5 = "System.Net.Sockets" ascii //weight: 2
        $x_2_6 = "ProtoBuf.Serializers.IProtoSerializer.Write" ascii //weight: 2
        $x_2_7 = "ProtoBuf.Serializers.IProtoTypeSerializer.HasCallbacks" ascii //weight: 2
        $x_2_8 = "FromBase64String" ascii //weight: 2
        $x_2_9 = "Microsoft.CodeAnalysis" ascii //weight: 2
        $x_2_10 = "WritePacked" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 8 of ($x_2_*))) or
            ((2 of ($x_6_*) and 5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_PureRat_AI_2147965657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AI!MTB"
        threat_id = "2147965657"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {73 20 00 00 06 73 d0 00 00 06 25 7e 41 06 00 04 28 ?? 0f 00 06 7e 42 06 00 04 28 ?? 0f 00 06 25 11 01 7e 43 06 00 04 28 ?? 0f 00 06 7e 44 06 00 04 28 ?? 0f 00 06 7e 3e 06 00 04 28 ?? 0f 00 06 11 05 28 ?? 00 00 2b 28 ?? 00 00 2b 7e 2e 06 00 04}  //weight: 6, accuracy: Low
        $x_2_2 = "CreateDecryptor" ascii //weight: 2
        $x_2_3 = "GZipStream" ascii //weight: 2
        $x_2_4 = "System.Net.Sockets" ascii //weight: 2
        $x_2_5 = "ProtoBuf.Serializers.IProtoSerializer.Write" ascii //weight: 2
        $x_2_6 = "ProtoBuf.Serializers.IProtoTypeSerializer.HasCallbacks" ascii //weight: 2
        $x_2_7 = "FromBase64String" ascii //weight: 2
        $x_2_8 = "Microsoft.CodeAnalysis" ascii //weight: 2
        $x_2_9 = "WritePacked" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureRat_AJ_2147966092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AJ!MTB"
        threat_id = "2147966092"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {06 2a 00 00 2e 28 23 0b 00 06 28 01 00 00 06 2a 13 30 04 00 9a 00 00 00 01 00 00 11 20}  //weight: 6, accuracy: High
        $x_6_2 = {28 25 0a 00 06 28 01 00 00 06 2a ae 7e}  //weight: 6, accuracy: High
        $x_5_3 = "m8DE" ascii //weight: 5
        $x_5_4 = "PureHVNC_Lib." ascii //weight: 5
        $x_2_5 = "CreateDecryptor" ascii //weight: 2
        $x_2_6 = "GZipStream" ascii //weight: 2
        $x_2_7 = "System.Net.Sockets" ascii //weight: 2
        $x_2_8 = "ProtoBuf.Serializers.IProtoSerializer.Write" ascii //weight: 2
        $x_2_9 = "ProtoBuf.Serializers.IProtoTypeSerializer.HasCallbacks" ascii //weight: 2
        $x_2_10 = "FromBase64String" ascii //weight: 2
        $x_2_11 = "Microsoft.CodeAnalysis" ascii //weight: 2
        $x_2_12 = "WritePacked" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 8 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 6 of ($x_2_*))) or
            ((2 of ($x_6_*) and 8 of ($x_2_*))) or
            ((2 of ($x_6_*) and 1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((2 of ($x_6_*) and 2 of ($x_5_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

