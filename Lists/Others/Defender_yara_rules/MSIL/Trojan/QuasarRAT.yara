rule Trojan_MSIL_QuasarRAT_B_2147839991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.B!MTB"
        threat_id = "2147839991"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 00 04 08 1a 58 91 5a d2 81}  //weight: 2, accuracy: High
        $x_1_2 = "server1.Resources.resources" ascii //weight: 1
        $x_1_3 = "uerijnq.Resources.resources" ascii //weight: 1
        $x_1_4 = "serv.Resources.resources" ascii //weight: 1
        $x_2_5 = "get_IsAttached" ascii //weight: 2
        $x_2_6 = "IsLogging" ascii //weight: 2
        $x_2_7 = "ConfuserEx" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_QuasarRAT_C_2147841131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.C!MTB"
        threat_id = "2147841131"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 11 04 02 11 04 91 11 0a 61 d2 9c}  //weight: 2, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_D_2147841143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.D!MTB"
        threat_id = "2147841143"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 0d 12 03 28 ?? 00 00 0a 28 ?? 00 00 0a 16 07 06 4a 1a 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_E_2147841944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.E!MTB"
        threat_id = "2147841944"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Client.Tests" ascii //weight: 2
        $x_2_2 = "eser.Client.Properties" ascii //weight: 2
        $x_1_3 = "set_WindowStyle" ascii //weight: 1
        $x_1_4 = "set_UseShellExecute" ascii //weight: 1
        $x_2_5 = "SHA256PRNG" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_MBBJ_2147842120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.MBBJ!MTB"
        threat_id = "2147842120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 0a 06 11 06 06 91 11 0b 61 d2 9c 06 0d 09 17 58 0a 06 11 06 8e 69 32 a2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_MBBK_2147842121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.MBBK!MTB"
        threat_id = "2147842121"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 08 18 58 0c 08 06 32}  //weight: 1, accuracy: Low
        $x_1_2 = "NEQ1QTkwMDAwMzAwMDAwMDA0MDAwMDAwRkZGRj" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_RDB_2147842630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.RDB!MTB"
        threat_id = "2147842630"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cc7fad03-816e-432c-9b92-001f2d358386" ascii //weight: 1
        $x_1_2 = "server1" ascii //weight: 1
        $x_1_3 = "koi" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_I_2147847361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.I!MTB"
        threat_id = "2147847361"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 ff b6 ff 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 9e 00 00 00 5e 04 00 00 4e 01 00 00 d7 13}  //weight: 2, accuracy: High
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "GetTempPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_K_2147848602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.K!MTB"
        threat_id = "2147848602"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 bd a2 3f 09 0f 00 00 00 b8 00 33 00 06 00 00 01 00 00 00 60 00 00 00 28 00 00 00 5c 00 00 00 6f 00 00 00 20}  //weight: 2, accuracy: High
        $x_2_2 = "w3wp.exe" wide //weight: 2
        $x_2_3 = "aspnet_wp.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_L_2147848604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.L!MTB"
        threat_id = "2147848604"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 95 02 28 c9 03 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 2e 00 00 00 0c 00 00 00 2b 00 00 00 36}  //weight: 2, accuracy: High
        $x_2_2 = "LzmaDecoder" ascii //weight: 2
        $x_2_3 = "BitDecoder" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_J_2147848901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.J!MTB"
        threat_id = "2147848901"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 bd a2 3f 09 0b 00 00 00 b8 00 33 00 02 00 00 01 00 00 00 69 00 00 00 4e 00 00 00 9c 00 00 00 ca}  //weight: 2, accuracy: High
        $x_2_2 = "w3wp.exe" wide //weight: 2
        $x_2_3 = "aspnet_wp.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_N_2147849924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.N!MTB"
        threat_id = "2147849924"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 bf a3 3f 09 1f 00 00 00 ba 01 33 00 16 00 00 01 00 00 00 b4 00 00 00 e0 00 00 00 5d 04 00 00 c0 05}  //weight: 2, accuracy: High
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_R_2147851141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.R!MTB"
        threat_id = "2147851141"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 00 04 08 16 07 16 1f 10 28 ?? ?? 00 06 7e ?? ?? 00 04 08 16 07 1f 0f 1f 10 28}  //weight: 2, accuracy: Low
        $x_1_2 = "GetTempFileName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_S_2147851152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.S!MTB"
        threat_id = "2147851152"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 1f 0b 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 73 ?? 01 00 0a 0c 7e ?? 03 00 04 07 7e ?? 03 00 04 08 1f 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_RDC_2147851578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.RDC!MTB"
        threat_id = "2147851578"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 06 6f 2c 00 00 0a 1f 20 06 6f 2c 00 00 0a 8e 69 1f 20 59 6f 03 01 00 0a 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_RDD_2147852575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.RDD!MTB"
        threat_id = "2147852575"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 12 00 28 47 01 00 0a 12 00 28 48 01 00 0a 20 20 00 cc 00 28 12 00 00 06 26 11 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_U_2147894398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.U!MTB"
        threat_id = "2147894398"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 9f a2 29 09 03 00 00 00 fe 01 33 00 00 00 00 01 00 00 00 44 00 00 00 30 00 00 00 32 01 00 00 24 01}  //weight: 2, accuracy: High
        $x_2_2 = "-netz.resources" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_RDE_2147894639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.RDE!MTB"
        threat_id = "2147894639"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "187b3b12-185d-4ca8-b198-f8fff0105727" ascii //weight: 1
        $x_1_2 = "BTC Clipper" ascii //weight: 1
        $x_1_3 = "Decompress" ascii //weight: 1
        $x_1_4 = "Decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_V_2147897051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.V!MTB"
        threat_id = "2147897051"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 0d 09 72 ?? 00 00 70 28 ?? 00 00 0a 02 7b ?? 00 00 04 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 08 73 ?? 00 00 0a 13 06 11 06 11 04 16 73 ?? 00 00 0a 13 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_KAA_2147900779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.KAA!MTB"
        threat_id = "2147900779"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 8e 69 5d 1f ?? 58 1f ?? 58 1f ?? 59 91 61 28 ?? 00 00 0a 03 08 20 ?? ?? 00 00 58 20 ?? ?? 00 00 59 03 8e 69 5d 91}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_X_2147903535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.X!MTB"
        threat_id = "2147903535"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 9c 06 17 d6 0a 11 ?? 17 d6 13}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 20 ff 00 00 00 fe}  //weight: 2, accuracy: High
        $x_2_3 = {17 da 17 d6 8d ?? ?? ?? 01 0d 16 0a 16 07 17 da}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_W_2147904323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.W!MTB"
        threat_id = "2147904323"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8e 69 6a 5d 69 06}  //weight: 2, accuracy: High
        $x_2_2 = {8e 69 6a 5d 69 91 02 08 02 8e 69 6a 5d 69 91 61 06}  //weight: 2, accuracy: High
        $x_2_3 = {08 17 6a 58 06}  //weight: 2, accuracy: High
        $x_2_4 = {8e 69 6a 5d 69 91 59}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_Y_2147905351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.Y!MTB"
        threat_id = "2147905351"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 08 03 8e 69 5d 1d 59 1d 58 03 08 03 8e 69 5d}  //weight: 2, accuracy: High
        $x_2_2 = {59 17 59 91 07 08 07 8e 69 5d}  //weight: 2, accuracy: High
        $x_2_3 = {59 17 59 91 61 03 08}  //weight: 2, accuracy: High
        $x_2_4 = {5d 19 59 19 58 d2 9c 08 17 58 0c}  //weight: 2, accuracy: High
        $x_2_5 = {08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_KAB_2147907489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.KAB!MTB"
        threat_id = "2147907489"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 0c 02 00 25 20 01 00 00 00 58 fe 0e 02 00 6f ?? 00 00 0a 61 d2 6f ?? 00 00 0a fe 0c 02 00 fe 0c 00 00 6f ?? 00 00 0a 5d fe 0e 02 00 fe 0c 04 00 20 01 00 00 00 58 fe 0e 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_RDF_2147914789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.RDF!MTB"
        threat_id = "2147914789"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 6f 4b 01 00 0a 13 07 73 9b 00 00 0a 13 04 11 04 11 07 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_ARA_2147916338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.ARA!MTB"
        threat_id = "2147916338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 06 07 02 07 91 18 63 02 07 91 1c 62 60 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e1}  //weight: 2, accuracy: High
        $x_2_2 = {00 02 07 91 0c 08 66 d2 0c 08 20 f0 00 00 00 5f 1a 63 08 1f 0f 5f 1a 62 60 d2 0c 06 07 08 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d d2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_KAV_2147919573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.KAV!MTB"
        threat_id = "2147919573"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "A722A020070280" wide //weight: 3
        $x_3_2 = "A25723516007" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_BN_2147933830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.BN!MTB"
        threat_id = "2147933830"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f}  //weight: 2, accuracy: Low
        $x_1_2 = {0e 04 05 6f ?? 00 00 0a 59 0a 06 05 28 ?? 00 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_3 = {0a 07 17 58 0b}  //weight: 1, accuracy: High
        $x_1_4 = {0c 07 08 28 ?? 00 00 06 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_SEDA_2147934599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.SEDA!MTB"
        threat_id = "2147934599"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 2a}  //weight: 3, accuracy: Low
        $x_2_2 = {02 03 04 6f ?? 00 00 0a 0b 0e 04 05 6f ?? 00 00 0a 59 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_NIT_2147937966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.NIT!MTB"
        threat_id = "2147937966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {38 27 00 00 00 28 ?? 00 00 0a 72 01 00 00 70 28 ?? 00 00 0a 25 11 01 28 ?? 00 00 0a 28 ?? 00 00 0a 26 20 02 00 00 00 38 bb ff ff ff 38 66 00 00 00 20 04 00 00 00 fe 0e 03 00 38 a4 ff ff ff 11 04 72 0b 00 00 70 6f 08 00 00 0a 6f 09 00 00 0a 13 01 20 00 00 00 00 7e 0b 00 00 04 7b 30 00 00 04 3a 81 ff ff ff 26 20 01 00 00 00 38 76 ff ff ff 11 01 3a 8d ff ff ff 20 00 00 00 00 7e 0b 00 00 04 7b 48 00 00 04 3a 5b ff ff ff 26 20 00 00 00 00 38 50 ff ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = "WriteAllBytes" ascii //weight: 2
        $x_2_3 = "GetByteArrayAsync" ascii //weight: 2
        $x_1_4 = "FromMinutes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRAT_DB_2147939453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRAT.DB!MTB"
        threat_id = "2147939453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "136"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "SharpBeacon-master" ascii //weight: 100
        $x_10_2 = "DllCanUnloadNow" ascii //weight: 10
        $x_10_3 = {68 00 74 00 74 00 70 00 [0-1] 3a 00 2f 00 2f 00 [0-100] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_4 = {68 74 74 70 [0-1] 3a 2f 2f [0-100] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_5 = "amsi.dll" ascii //weight: 10
        $x_1_6 = "AMSIBypass" ascii //weight: 1
        $x_1_7 = "Patch" ascii //weight: 1
        $x_1_8 = "GetProcAddress" ascii //weight: 1
        $x_1_9 = "FindAddress" ascii //weight: 1
        $x_1_10 = "LoadLibrary" ascii //weight: 1
        $x_1_11 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 6 of ($x_1_*))) or
            ((1 of ($x_100_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

