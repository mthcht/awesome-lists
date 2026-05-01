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

rule Trojan_MSIL_PureRat_AK_2147966607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AK!MTB"
        threat_id = "2147966607"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {28 01 00 00 06 2a 00 ae 7e}  //weight: 6, accuracy: High
        $x_6_2 = {28 24 0b 00 06 28 01 00 00 06 2a}  //weight: 6, accuracy: High
        $x_5_3 = "m8DD" ascii //weight: 5
        $x_5_4 = "m8DE" ascii //weight: 5
        $x_5_5 = "PureHVNC_Lib." ascii //weight: 5
        $x_2_6 = "CreateDecryptor" ascii //weight: 2
        $x_2_7 = "GZipStream" ascii //weight: 2
        $x_2_8 = "System.Net.Sockets" ascii //weight: 2
        $x_2_9 = "ProtoBuf.Serializers.IProtoSerializer.Write" ascii //weight: 2
        $x_2_10 = "ProtoBuf.Serializers.IProtoTypeSerializer.HasCallbacks" ascii //weight: 2
        $x_2_11 = "FromBase64String" ascii //weight: 2
        $x_2_12 = "Microsoft.CodeAnalysis" ascii //weight: 2
        $x_2_13 = "WritePacked" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 6 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 8 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 6 of ($x_2_*))) or
            ((1 of ($x_6_*) and 3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_6_*) and 8 of ($x_2_*))) or
            ((2 of ($x_6_*) and 1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((2 of ($x_6_*) and 2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_6_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_PureRat_AL_2147966990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AL!MTB"
        threat_id = "2147966990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {04 00 04 28 ?? 0a 00 06 7e ?? 04 00 04 28 ?? 0a 00 06 7e ?? 04 00 04 28 ?? 0a 00 06 0a 06 7e ?? 04 00 04 28 ?? 0a 00 06 1f 24 28 ?? 00 00 0a 7e ?? 04 00 04 28 ?? 0a 00 06 7e ?? 04 00 04 28 ?? 0a 00 06 39 05 00 00 00 dd 4b 00 00 00 73 10 00 00 0a 25 17 7e}  //weight: 6, accuracy: Low
        $x_5_2 = "m8DD" ascii //weight: 5
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
            ((3 of ($x_5_*) and 6 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 8 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 6 of ($x_2_*))) or
            ((1 of ($x_6_*) and 3 of ($x_5_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_PureRat_AM_2147967202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AM!MTB"
        threat_id = "2147967202"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {02 75 0c 00 00 02 0a 06 3a 05 00 00 00 dd 9e 00 00 00 06 6f ?? 00 00 06 28 ?? 00 00 06 0b 07 75 08 00 00 02 39 0b 00 00 00 03 28 ?? 00 00 06 38 49 00 00 00 07 75 06 00 00 02 39 1b 00 00 00 17 80 04 00 00 04 28 ?? 00 00 06 28 ?? 00 00 06 03 28 ?? 00 00 06 38 23 00 00 00 07 75 07 00 00 02 39 18}  //weight: 6, accuracy: Low
        $x_2_2 = "Steam Blocker Client for PureRAT" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureRat_AN_2147967269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AN!MTB"
        threat_id = "2147967269"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {0b 38 37 00 00 00 06 07 a3 11 00 00 01 0c 08 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 39 06 00 00 00 08 6f ?? 00 00 0a dd 06 00 00 00 26 dd 00 00 00 00 07 17 58 0b 07 06 8e 69 32 c3 dd 06 00 00 00 26 dd 00 00 00 00 20 88 13 00 00 28}  //weight: 6, accuracy: Low
        $x_2_2 = "Steam Blocker Client for PureRAT" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureRat_AO_2147967447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AO!MTB"
        threat_id = "2147967447"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {7e 06 00 00 04 39 10 00 00 00 7e 06 00 00 04 6f ?? 00 00 0a 39 01 00 00 00 2a 7e f1 02 00 04 25 3a 17 00 00 00 26 7e ef 02 00 04 fe 06 8e 06 00 06 73 11 00 00 0a 25 80 f1 02 00 04 73 12 00 00 0a 80 06 00 00 04 7e 06 00 00 04 17 6f ?? 00 00 0a 7e 06 00 00 04 6f ?? 00 00 0a 2a}  //weight: 6, accuracy: Low
        $x_2_2 = "Steam Blocker Client for PureRAT" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureRat_AP_2147967737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AP!MTB"
        threat_id = "2147967737"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {11 02 7e 21 06 00 04 28 ?? 0e 00 06 1f 24 28 ?? 00 00 0a 7e 21 06 00 04 28 ?? 0e 00 06 7e 22 06 00 04 28 ?? 0e 00 06 39 1f 00 00 00 20 00 00 00 00 7e 07 06 00 04 7b ef 05 00 04 3a 89 ff ff ff 26 20 06 00 00 00 38 7e ff ff ff 73 11 00 00 0a 25 17 7e 23 06 00 04}  //weight: 6, accuracy: Low
        $x_5_2 = "m8DD" ascii //weight: 5
        $x_5_3 = "m8DE" ascii //weight: 5
        $x_5_4 = "m8DC" ascii //weight: 5
        $x_5_5 = "PureHVNC_Lib." ascii //weight: 5
        $x_2_6 = "CreateDecryptor" ascii //weight: 2
        $x_2_7 = "GZipStream" ascii //weight: 2
        $x_2_8 = "System.Net.Sockets" ascii //weight: 2
        $x_2_9 = "ProtoBuf.Serializers.IProtoSerializer.Write" ascii //weight: 2
        $x_2_10 = "ProtoBuf.Serializers.IProtoTypeSerializer.HasCallbacks" ascii //weight: 2
        $x_2_11 = "FromBase64String" ascii //weight: 2
        $x_2_12 = "Microsoft.CodeAnalysis" ascii //weight: 2
        $x_2_13 = "WritePacked" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 6 of ($x_2_*))) or
            ((4 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 8 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 6 of ($x_2_*))) or
            ((1 of ($x_6_*) and 3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 4 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_PureRat_AQ_2147967858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AQ!MTB"
        threat_id = "2147967858"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {73 10 00 00 0a 25 17 7e 1f 06 00 04 28 ?? 0e 00 06 25 17 7e 20 06 00 04 28 ?? 0e 00 06 25 11 03 7e 21 06 00 04 28 ?? 0e 00 06 7e 22 06 00 04 28 ?? 0e 00 06 26 20 09 00 00 00 7e 10 06 00 04 7b c6 05 00 04 39 8f ff ff ff 26 20 00 00 00 00 38 84 ff ff ff dd 12 ff ff ff 20 09}  //weight: 6, accuracy: Low
        $x_5_2 = "m8DD" ascii //weight: 5
        $x_5_3 = "m8DE" ascii //weight: 5
        $x_5_4 = "m8DC" ascii //weight: 5
        $x_5_5 = "PureHVNC_Lib." ascii //weight: 5
        $x_2_6 = "CreateDecryptor" ascii //weight: 2
        $x_2_7 = "GZipStream" ascii //weight: 2
        $x_2_8 = "System.Net.Sockets" ascii //weight: 2
        $x_2_9 = "ProtoBuf.Serializers.IProtoSerializer.Write" ascii //weight: 2
        $x_2_10 = "ProtoBuf.Serializers.IProtoTypeSerializer.HasCallbacks" ascii //weight: 2
        $x_2_11 = "FromBase64String" ascii //weight: 2
        $x_2_12 = "Microsoft.CodeAnalysis" ascii //weight: 2
        $x_2_13 = "WritePacked" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 6 of ($x_2_*))) or
            ((4 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 8 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 6 of ($x_2_*))) or
            ((1 of ($x_6_*) and 3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 4 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_PureRat_AR_2147968184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AR!MTB"
        threat_id = "2147968184"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {72 59 00 00 70 28 14 00 00 0a 0b 72 9b 00 00 70 28 14 00 00 0a 0c 28 15 00 00 0a 13 06 11 06 07 6f 16 00 00 0a 11 06 08 6f 17 00 00 0a 11 06 17 6f 18 00 00 0a 11 06 18 6f 19 00 00 0a 11 06 6f 1a 00 00 0a 13 07 11 07 06 16 06 8e 69 6f 1b 00 00 0a 0d de 18}  //weight: 6, accuracy: High
        $x_5_2 = "PayloadSource.zip" ascii //weight: 5
        $x_1_3 = "GZipStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

