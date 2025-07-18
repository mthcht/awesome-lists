rule Trojan_MSIL_AsyncRAT_MWB_2147818576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MWB!MTB"
        threat_id = "2147818576"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 0b 2b 22 00 06 02 02 6f ?? ?? ?? 0a 17 59 07 59 6f ?? ?? ?? 0a 8c ?? ?? ?? 01 28 ?? ?? ?? 0a 0a 00 07 17 58 0b 07 02 6f ?? ?? ?? 0a fe 04 0d 09 2d d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BK_2147824749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BK!MTB"
        threat_id = "2147824749"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {57 95 b6 29 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 8d 00 00 00 4d 00 00 00 bb 00 00 00 ea 02}  //weight: 4, accuracy: High
        $x_2_2 = "GetManifestResourceStream" ascii //weight: 2
        $x_2_3 = "Reverse" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ABK_2147827753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ABK!MTB"
        threat_id = "2147827753"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 06 28 ?? ?? ?? 0a 0a 72 ?? ?? ?? 70 0b 72 ?? ?? ?? 70 25 28 ?? ?? ?? 0a 26 72 ?? ?? ?? 70 0c 72 ?? ?? ?? 70 0d 06 06 28 ?? ?? ?? 0a 0d 09 28 ?? ?? ?? 0a 09 09 28 ?? ?? ?? 0a 0d 72 ?? ?? ?? 70 13 04}  //weight: 5, accuracy: Low
        $x_1_2 = "HttpDownloadFile" ascii //weight: 1
        $x_1_3 = "GetResponseStream" ascii //weight: 1
        $x_1_4 = "DeleteDirectory" ascii //weight: 1
        $x_1_5 = "powermonster" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PAA_2147827835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PAA!MTB"
        threat_id = "2147827835"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 06 11 06 08 6f ?? ?? ?? 0a 11 06 18 6f ?? ?? ?? 0a 11 06 18 6f ?? ?? ?? 0a 11 06 0d 09 6f ?? ?? ?? 0a 13 04 11 04 06 16 06 8e 69 6f ?? ?? ?? 0a 13 05 28 42 00 00 0a 11 05 6f ?? ?? ?? 0a 13 07 de 14 09 2c 06 09 6f ?? ?? ?? 0a dc 07 2c 06 07 6f ?? ?? ?? 0a dc 11 07 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {72 f7 07 00 70 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 72 07 08 00 70 03 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 26 14 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NH_2147827956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NH!MTB"
        threat_id = "2147827956"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 00 16 2d f8 16 2d d0 2a 28 ?? ?? ?? 0a 2b cf 03 2b ce 28 ?? ?? ?? 0a 2b ce 6f ?? ?? ?? 0a 2b cf 28 ?? ?? ?? 0a 2b ca 28 ?? ?? ?? 0a 2b ce}  //weight: 10, accuracy: Low
        $x_1_2 = "ToInt32" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "DynamicInvoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NYA_2147828353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NYA!MTB"
        threat_id = "2147828353"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 25 06 6f ?? ?? ?? 0a 25 18 6f ?? ?? ?? 0a 25 18 6f ?? ?? ?? 0a 25 6f ?? ?? ?? 0a 0b 04 07 02 16 02 8e 69 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {47 15 02 08 09 00 00 00 00 fa 01 33 00 16 c4 00 01 00 00 00 2f 00 00 00 03 00 00 00 09 00 00 00 05 00 00 00 3a 00 00 00 0e 00 00 00 04 00 00 00 01 00 00 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ABH_2147828471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ABH!MTB"
        threat_id = "2147828471"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 17 a2 0b 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 79 00 00 00 26 00 00 00 2f 00 00 00 48 03 00 00 54 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "Notpad_SP_" ascii //weight: 1
        $x_1_3 = "get_WebServices" ascii //weight: 1
        $x_1_4 = "GetDomain" ascii //weight: 1
        $x_1_5 = "RemotingProxy" ascii //weight: 1
        $x_1_6 = "BufferedStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_DA_2147829169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.DA!MTB"
        threat_id = "2147829169"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "LLLMLLeLtLhLoLdL0LLL" wide //weight: 10
        $x_10_2 = "NNMNNeNNtNNhNoNNdN0NN" wide //weight: 10
        $x_10_3 = "OOMOOeOOtOOhOOoOdOO0OO" wide //weight: 10
        $x_1_4 = "LCC_SAMS_Project.Resources" wide //weight: 1
        $x_1_5 = "GetExportedTypes" wide //weight: 1
        $x_1_6 = "ExecuteReader" wide //weight: 1
        $x_1_7 = "Create__Instance__" ascii //weight: 1
        $x_1_8 = "Replace" ascii //weight: 1
        $x_1_9 = "ToString" ascii //weight: 1
        $x_1_10 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_AsyncRAT_ABD_2147829603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ABD!MTB"
        threat_id = "2147829603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 06 07 2c 00 72 b5 ?? ?? 70 72 92 ?? ?? 70 28 1a ?? ?? 06 28 31 ?? ?? 0a 0b 72 b2 ?? ?? 70 72 92 ?? ?? 70 28 ?? ?? ?? 06 28 31}  //weight: 5, accuracy: Low
        $x_5_2 = {02 08 28 38 ?? ?? 0a 28 39 ?? ?? 0a 03 08 03 6f 10 ?? ?? 0a 5d 17 58 28 38 ?? ?? 0a 28 39 ?? ?? 0a 59 13 04 06 11 04}  //weight: 5, accuracy: Low
        $x_1_3 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PAB_2147830860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PAB!MTB"
        threat_id = "2147830860"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 13 08 08 28 ?? ?? ?? 0a 13 09 19 8d ?? ?? ?? 01 13 0b 11 0b 16 11 08 a2 11 0b 17 7e ?? ?? ?? 0a a2 11 0b 18 09 a2 11 0b 13 0a 11 09 72 ?? ?? ?? 70 17 8d ?? ?? ?? 01 13 0c 11 0c 16 11 05 a2 11 0c 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 17 8d ?? ?? ?? 01 13 0d 11 0d 16 11 07 a2 11 0d 28 ?? ?? ?? 0a 20 00 01 00 00 14 14 11 0a 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 26 17 28 ?? ?? ?? 0a 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_I_2147831655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.I!MSR"
        threat_id = "2147831655"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "188.227.57.46/folder/core_Hvovthzn.jpg" ascii //weight: 1
        $x_1_2 = "Hadgbbpi.Tynwpfgdqqzvie" ascii //weight: 1
        $x_1_3 = "Start-Sleep -Seconds 30" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RD_2147833128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RD!MTB"
        threat_id = "2147833128"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mou3li_Encription_KEY" wide //weight: 1
        $x_1_2 = "Mou created this crypter" wide //weight: 1
        $x_2_3 = {07 28 07 00 00 0a 6f 08 00 00 0a 14 14 6f 09 00 00 0a 26}  //weight: 2, accuracy: High
        $x_2_4 = {11 04 17 58 20 00 01 00 00 5d 13 04 11 05 07 11 04 91 58 20 00 01 00 00 5d 13 05 07 11 04 91 0d 07 11 04 07 11 05 91 9c 07 11 05 09 9c 07 11 04 91 07 11 05 91 58 20 00 01 00 00 5d 13 07 02 11 06 8f 0a 00 00 01 25 71 0a 00 00 01 07 11 07 91 61 d2 81 0a 00 00 01 11 06 17 58 13 06 11 06 02 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDB_2147833129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDB!MTB"
        threat_id = "2147833129"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 28 0e 00 00 0a 6f 0f 00 00 0a 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 6f 10 00 00 0a 28 11 00 00 0a 0a 28 12 00 00 0a 72 ?? ?? ?? ?? 28 0e 00 00 0a 6f 0f 00 00 0a 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 6f 10 00 00 0a 28 13 00 00 0a 28 11 00 00 0a 0b 72 ?? ?? ?? ?? 0c 73 14 00 00 0a 0d 09 28 15 00 00 0a 08 6f 16 00 00 0a 6f 17 00 00 0a 00 09 28 15 00 00 0a 08 6f 16 00 00 0a 6f 18 00 00 0a 00 09 09 6f 19 00 00 0a 09 6f 1a 00 00 0a 6f 1b 00 00 0a 13 04 73 1c 00 00 0a 13 05 11 05 11 04 17 73 1d 00 00 0a 13 06 07}  //weight: 2, accuracy: Low
        $x_2_2 = {28 20 00 00 0a 58 6f 21 00 00 0a 28 22 00 00 0a 13 08 11 06 11 08 16 11 08 8e 69 6f 23 00 00 0a 00 11 06 6f 24 00 00 0a 00 11 05 6f 25 00 00 0a 28 26 00 00 0a 13 09 11 09 6f 27 00 00 0a 14 16 8d 03 00 00 01 6f 28 00 00 0a 26 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_B_2147833621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.B!MTB"
        threat_id = "2147833621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0b 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0a 73 ?? 00 00 0a 0c 08 06 6f ?? 00 00 0a 00 08 18 6f ?? 00 00 0a 00 08 6f ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 13 04 08 6f ?? 00 00 0a 00 11 04 13 05}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_B_2147833621_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.B!MTB"
        threat_id = "2147833621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 07 00 00 70 0a 73 17 00 00 0a 73 18 00 00 0a 0b 07 6f 19 00 00 0a 72 c0 dd 0f 70 7e 01 00 00 04 28 03 00 00 06 6f 1a 00 00 0a 26 07 6f 19 00 00 0a 72 22 de 0f 70 7e 01 00 00 04 28 03 00 00 06 6f 1a 00 00 0a 26 07 17 6f 1b 00 00 0a 07 17 8d 14 00 00 01}  //weight: 2, accuracy: High
        $x_1_2 = "8501d172-1ebb-4613-87a4-eef7f2546a27" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDC_2147833883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDC!MTB"
        threat_id = "2147833883"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {18 5b 2b 41 08 18 6f 25 00 00 0a 1f 10 28 26 00 00 0a 9c 08 18 58 16 2d fb 0c 08 18}  //weight: 2, accuracy: High
        $x_1_2 = "GetType" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "GetResponse" ascii //weight: 1
        $x_1_5 = "GetResponseStream" ascii //weight: 1
        $x_2_6 = "//asemcosoluciones.com/loader/uploads/" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDD_2147834165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDD!MTB"
        threat_id = "2147834165"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 28 13 00 00 0a 28 27 00 00 0a 0a 06 28 ?? ?? ?? ?? 6f 1a 00 00 0a 0b 07 2c ?? 02 20 00 01 00 00 8d 0d 00 00 01 7d ?? ?? ?? ?? 07 02 7b ?? ?? ?? ?? 16 02 7b ?? ?? ?? ?? 8e 69 6f 2c 00 00 0a 26}  //weight: 2, accuracy: Low
        $x_2_2 = {08 06 08 06 93 02 7b ?? ?? ?? ?? 07 91 04 60 61 d1 9d 06 17 59 25 0a 16 2f}  //weight: 2, accuracy: Low
        $x_1_3 = "529bbdc6275ea6ec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDE_2147835631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDE!MTB"
        threat_id = "2147835631"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c7GtJhJiaIEA84wwU6.Cqb6H5rEnKIUIcLlp4" wide //weight: 1
        $x_1_2 = "bIRrbBaBuo9yJnQ3rs.7QO3EZlkA06hGUSDsk" wide //weight: 1
        $x_1_3 = "kernel32" ascii //weight: 1
        $x_1_4 = "GetProcAddress" ascii //weight: 1
        $x_1_5 = "Virtual " wide //weight: 1
        $x_1_6 = "Protect" wide //weight: 1
        $x_1_7 = "Alloc" wide //weight: 1
        $x_1_8 = "GetDelegateForFunctionPointer" wide //weight: 1
        $x_1_9 = "uu.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NZQ_2147836547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NZQ!MTB"
        threat_id = "2147836547"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 13 00 61 fe 0e 1a 00 fe 0c 16 00 1f 0f 64 fe 0c 16 00 1f 11 62 60 fe 0e 16 00 fe 0c 12 00 fe 0c 12 00 1b 64 61 fe 0e 12 00}  //weight: 1, accuracy: High
        $x_1_2 = "8f11-c5d43061a100" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ABGE_2147837427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ABGE!MTB"
        threat_id = "2147837427"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0d 09 12 02 28 08 00 00 06 00 73 12 00 00 0a 13 04 11 04 08 6f 13 00 00 0a 17 73 14 00 00 0a 13 05 00 11 05 02 16 02 8e 69 6f 15 00 00 0a 00 11 05 6f 16 00 00 0a 00 00 de 0d 11 05 2c 08 11 05 6f 0a 00 00 0a 00 dc 11 04 6f 17 00 00 0a 10 00 02 13 06 2b 00 11 06 2a}  //weight: 2, accuracy: High
        $x_1_2 = "Katyusha" wide //weight: 1
        $x_1_3 = "Soviet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NAD_2147838211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NAD!MTB"
        threat_id = "2147838211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 01 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 2c 19 72 ?? 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70}  //weight: 1, accuracy: Low
        $x_1_2 = {28 1e 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70}  //weight: 1, accuracy: Low
        $x_1_3 = "m_MyWebServicesObjectProvider" ascii //weight: 1
        $x_1_4 = "m_UserObjectProvider" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NT_2147838700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NT!MTB"
        threat_id = "2147838700"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 08 9a 28 1e 00 00 0a 6f ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 2c 04 17 0d de 5d 08 17 58 0c 08 06 8e}  //weight: 5, accuracy: Low
        $x_1_2 = "CsharpPureFinder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NT_2147838700_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NT!MTB"
        threat_id = "2147838700"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 17 00 00 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 28 ?? ?? ?? 0a 72 ?? ?? ?? 70}  //weight: 5, accuracy: Low
        $x_5_2 = {6f 15 00 00 0a 13 05 11 04 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 2c 73 11 04 11 04 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 58 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 11 05 28 ?? ?? ?? 06 28 ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_3 = "Xub.Form1.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NU_2147838854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NU!MTB"
        threat_id = "2147838854"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 b8 00 00 00 20 ?? ?? ?? 00 59 fe ?? ?? 00 20 ?? ?? ?? 00 38 ?? ?? ?? 00 11 11 11 10 11 01 38 ?? ?? ?? 00 13 04 20 ?? ?? ?? 00 fe ?? ?? 00 38 ?? ?? ?? 00}  //weight: 5, accuracy: Low
        $x_1_2 = "GeneralFile.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_E_2147839035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.E!MTB"
        threat_id = "2147839035"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 04 17 8d ?? 00 00 01 0a 06 16 05 a2 06 28 ?? ?? 00 0a 0e 04 04 16 8d ?? 00 00 01 28 ?? ?? 00 0a 0e 05 04 18 8d ?? 00 00 01 0b 07 16 16 8d ?? 00 00 01 a2 07 28}  //weight: 2, accuracy: Low
        $x_1_2 = "get_CurrentDomain" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_G_2147839640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.G!MTB"
        threat_id = "2147839640"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "file:///" wide //weight: 2
        $x_2_2 = "@ECHO OFF" wide //weight: 2
        $x_2_3 = "ping 127.0.0.1 > nul" wide //weight: 2
        $x_2_4 = "echo j | del /F" wide //weight: 2
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "CheckRemoteDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_EB_2147839734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.EB!MTB"
        threat_id = "2147839734"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 57 d4 02 fc c9 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 34 00 00 00 17 00 00 00 58 00 00 00 a9 00 00 00 50 00 00 00 11 00 00 00 02 00 00 00 03 00 00 00 17}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "386d05db-6b0c-4499-8515-2fb53b58e507" ascii //weight: 1
        $x_1_4 = "ConfuserEx v1.0.0" ascii //weight: 1
        $x_1_5 = "Client.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDF_2147839823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDF!MTB"
        threat_id = "2147839823"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KMSLocalServer" ascii //weight: 1
        $x_1_2 = "dPqLCOBUxlULbXCvCT.BampERXWdA9jWLsito" ascii //weight: 1
        $x_1_3 = "nVF9ahaPwEAA3Eecev.PwSxkyla6Vn3H8imOI" ascii //weight: 1
        $x_1_4 = "EH7PrQgb7lw2G3xgXP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_I_2147840035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.I!MTB"
        threat_id = "2147840035"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 03 5d 0c 08 8c}  //weight: 2, accuracy: High
        $x_2_2 = {04 05 60 04 66 05}  //weight: 2, accuracy: High
        $x_2_3 = {66 60 5f 8c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AT_2147840100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AT!MTB"
        threat_id = "2147840100"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 e8 03 00 00 28 ?? ?? ?? 0a 00 00 07 17 58 0b 07 73 ?? ?? ?? 0a 17 19 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NY_2147840172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NY!MTB"
        threat_id = "2147840172"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 6b 00 00 0a 25 26 6f ?? ?? ?? 0a 25 26 13 67 11 67 14 20 ?? ?? ?? 00 28 ?? ?? ?? 06 25 26 16 28 ?? ?? ?? 06}  //weight: 5, accuracy: Low
        $x_1_2 = "CryptoObfuscator_Output" ascii //weight: 1
        $x_1_3 = "v4.My.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_M_2147840917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.M!MTB"
        threat_id = "2147840917"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 04 07 09 16 6f ?? 00 00 0a 25 26 13 04 12 04 28 ?? 00 00 0a 25 26 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_CA_2147841054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.CA!MTB"
        threat_id = "2147841054"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {58 fe 0e 0a 00 91 fe ?? ?? ?? 61 d2 9c fe ?? ?? ?? 20 ?? ?? ?? ?? 5f 20 ?? ?? ?? ?? 40 ?? ?? ?? ?? fe ?? ?? ?? fe ?? ?? ?? 58 fe ?? ?? ?? fe ?? ?? ?? 20 ?? ?? ?? ?? 64 fe ?? ?? ?? 20 ?? ?? ?? ?? 62 60 20 ?? ?? ?? ?? 5a fe ?? ?? ?? fe ?? ?? ?? 20 ?? ?? ?? ?? 64 fe ?? ?? ?? 20 ?? ?? ?? ?? 62 60 fe ?? ?? ?? fe ?? ?? ?? 20 ?? ?? ?? ?? 58 fe ?? ?? ?? fe ?? ?? ?? 6a 20 ?? ?? ?? ?? 6a 3f}  //weight: 10, accuracy: Low
        $x_1_2 = "cuckoomon.dll" ascii //weight: 1
        $x_1_3 = "SxIn.dll" ascii //weight: 1
        $x_1_4 = "cmdvrt32.dll" ascii //weight: 1
        $x_1_5 = "SbieDll.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ASR_2147841224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ASR!MTB"
        threat_id = "2147841224"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 a2 25 17 7e ?? ?? ?? 0a a2 25 18 09 a2 25 19 17 8c ?? ?? ?? 01 a2 13 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBAT_2147841639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBAT!MTB"
        threat_id = "2147841639"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 13 04 11 04 72 ff 00 00 70 15 16 28 ?? 00 00 0a 0d de 16}  //weight: 1, accuracy: Low
        $x_1_2 = "x44TQ2DrCewRHv2" ascii //weight: 1
        $x_1_3 = "nolane.Resources.resources" ascii //weight: 1
        $x_1_4 = "101b6b2515" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBAX_2147841711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBAX!MTB"
        threat_id = "2147841711"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 07 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 08 6f ?? 00 00 0a 02 50 16 02 50 8e 69 6f ?? 00 00 0a 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "Coronovirus.Coronovirus" wide //weight: 1
        $x_1_3 = {4d 00 4c 00 48 00 4a 00 66 00 44 00 44 00 44 00 53 00 5a 00 00 2f 43 00 6f 00 72 00 6f 00 6e 00 6f 00 76}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBAZ_2147841720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBAZ!MTB"
        threat_id = "2147841720"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 13 07 09 28 ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 13 08 11 08 16 11 07 16 1f 10 28 ?? 00 00 0a 11 08 16 11 07 1f 0f 1f 10 28 83 00 00 0a 06 11 07}  //weight: 1, accuracy: Low
        $x_1_2 = "sgRtPcqXpbfFtrlDAWtRWTfixSTdniLb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBBG_2147841734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBBG!MTB"
        threat_id = "2147841734"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 02 8e b7 17 da 13 10 13 0f 2b 30 11 0c 11 0f 02 11 0f 91 11 06 61 11 09 11 08 91 61 b4 9c 11 08 03}  //weight: 1, accuracy: High
        $x_1_2 = "hMZYorumMaTElnI" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDI_2147842201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDI!MTB"
        threat_id = "2147842201"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fbc8c60f-8cd0-4b04-bfb9-b6dee12a74d9" ascii //weight: 1
        $x_1_2 = "WindowsApp1" ascii //weight: 1
        $x_1_3 = "j5wkyNJoEQPLa8Rspw" ascii //weight: 1
        $x_1_4 = "HRi1oSK7k1NQfXUmwB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBBV_2147842656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBBV!MTB"
        threat_id = "2147842656"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 14 20 d6 00 00 00 28 ?? 00 00 06 17 8d ?? 00 00 01 25 16 7e 0a 00 00 04 a2 25 0d 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 13 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NAR_2147842955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NAR!MTB"
        threat_id = "2147842955"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f f8 00 00 0a 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a 08}  //weight: 5, accuracy: Low
        $x_1_2 = "AsyncRAT-Client.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NAR_2147842955_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NAR!MTB"
        threat_id = "2147842955"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {38 9d 00 00 00 26 20 ?? ?? ?? 00 38 ?? ?? ?? 00 20 ?? ?? ?? b0 17 63 20 ?? ?? ?? 02 61 1a 63 20 ?? ?? ?? 02 58 07 5b 0b 20 ?? ?? ?? 00 fe ?? ?? 00 28 ?? ?? ?? 06 39 ?? ?? ?? 00 38 ?? ?? ?? 00 38 ?? ?? ?? 00 12 00}  //weight: 5, accuracy: Low
        $x_1_2 = "WindowsApp1.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_V_2147842980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.V!MTB"
        threat_id = "2147842980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "007Stub.g.resources" ascii //weight: 2
        $x_2_2 = "007Stub.Properties.Resources" ascii //weight: 2
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "CreateThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NRA_2147843461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NRA!MTB"
        threat_id = "2147843461"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 59 00 00 04 06 7e ?? ?? 00 04 06 91 20 ?? ?? 00 00 59 d2 9c 00 06 17 58 0a 06 7e ?? ?? 00 04 8e 69 fe 04 0b 07 2d d7}  //weight: 5, accuracy: Low
        $x_1_2 = "Kanhal.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBCP_2147843958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBCP!MTB"
        threat_id = "2147843958"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 09 41 00 07 09 73 00 07 09 73 00 07 09 65 00 07 09 6d 00 07 09 62 00 07 09 6c 00 07 09 79 00 07 09 01 03 07 09 01 1d 07 09 07 09 07 09 07 09 07 09 07 09 07 09 07 09 07 09 07 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_Y_2147843977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.Y!MTB"
        threat_id = "2147843977"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 08 06 08 91 07 08 07 28 ?? 00 00 06 25 26 69 5d 91 61 d2 9c 08 1a 28 ?? 00 00 06 58 0c}  //weight: 2, accuracy: Low
        $x_1_2 = "ResourceReader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBCX_2147844211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBCX!MTB"
        threat_id = "2147844211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 72 4b 23 00 70 6f ?? ?? ?? 0a 25 72 ed 23 00 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 29 24 00 70}  //weight: 1, accuracy: Low
        $x_1_2 = "bcd35dff-c91d-4508-87e0-f7f92118701d" ascii //weight: 1
        $x_1_3 = {65 00 72 00 72 00 2e 00 74 00 78 00 74 00 00 11 70 00 6c 00 73 00 63 00 2e 00 64 00 6c 00 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NNC_2147844512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NNC!MTB"
        threat_id = "2147844512"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 28 12 00 00 0a 25 26 0b 28 ?? 00 00 0a 25 26 07 16 07 8e 69 6f 28 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Lime_AsyncClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_EAP_2147844575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.EAP!MTB"
        threat_id = "2147844575"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {1b 2d 22 26 28 ?? 01 00 0a 06 6f ?? 01 00 0a 28 ?? 00 00 0a 15 2d 11 26 02 07 28 ?? 01 00 06 1c 2d 09 26 de 0c 0a 2b dc 0b 2b ed 0c 2b f5 26 de c9}  //weight: 3, accuracy: Low
        $x_2_2 = "WindowsFormsApp69.Properties.Resources" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PSKL_2147844907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PSKL!MTB"
        threat_id = "2147844907"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 03 00 00 01 0a 73 02 00 00 0a 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 25 16 06 16 1f 10 28 ?? ?? ?? 0a 16 06 1f 0f 1f 10 28 ?? ?? ?? 0a 25 06 6f ?? ?? ?? 0a 25 18 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 02 16 02 8e 69 6f 0a 00 00 0a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBCY_2147845037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBCY!MTB"
        threat_id = "2147845037"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 13 05 2b b9 16 0a 1e 13 05 2b b2 03 04 61 1f 17 59 06 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBDI_2147845054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBDI!MTB"
        threat_id = "2147845054"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 0d 00 07 08 7e ?? 00 00 04 28 ?? 00 00 06 6f ?? 01 00 0a 6f ?? 01 00 0a 00 07 18 6f ?? 01 00 0a 00 07 6f ?? 01 00 0a 13 04 02 13 05 11 04 11 05 16 11 05 8e 69 6f ?? 01 00 0a 0a de 28}  //weight: 1, accuracy: Low
        $x_1_2 = "f77a14962a9f" ascii //weight: 1
        $x_1_3 = "AsyncRAT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_EAQ_2147845240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.EAQ!MTB"
        threat_id = "2147845240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 06 0b 1f 20 8d ?? 00 00 01 25 d0 ?? 01 00 04 28 ?? 00 00 0a 0c 28 ?? 01 00 0a 03 6f ?? 00 00 0a 28 ?? 04 00 06 0d 73 ?? 01 00 0a 13 04 28 ?? 04 00 06 13 05 11 05 08 6f ?? 00 00 0a 11 05 09 6f ?? 01 00 0a 11 04 11 05 6f ?? 02 00 0a 17 73 ?? 01 00 0a 13 06 11 06 07 16 07 8e 69 6f ?? 01 00 0a 11 06 6f ?? 01 00 0a 11 04 6f ?? 01 00 0a 28}  //weight: 3, accuracy: Low
        $x_2_2 = "dbxqlcuy.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_W_2147845486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.W!MTB"
        threat_id = "2147845486"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Resource.reflect" wide //weight: 2
        $x_2_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" wide //weight: 2
        $x_2_3 = "DisableTaskMgr" wide //weight: 2
        $x_2_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_2_5 = "\\Service.exe" wide //weight: 2
        $x_2_6 = "WindowsUpdate" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NAS_2147845587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NAS!MTB"
        threat_id = "2147845587"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {64 60 fe 0c 14 00 61 fe ?? ?? 00 fe ?? ?? 00 20 ?? ?? ?? 55 5f fe ?? ?? 00 fe ?? ?? 00 20 ?? ?? ?? aa 5f fe ?? ?? 00 fe ?? ?? 00 20 ?? ?? ?? 00 64 fe ?? ?? 00 20 ?? ?? ?? 00 62 60}  //weight: 5, accuracy: Low
        $x_1_2 = "PyLibHosting" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NAS_2147845587_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NAS!MTB"
        threat_id = "2147845587"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {94 5b fe 0e 02 00 fe ?? ?? 00 20 ?? ?? ?? 1d 5a 20 ?? ?? ?? 79 61 38 ?? ?? ?? ff 38 ?? ?? ?? 00 fe ?? ?? 00 20 ?? ?? ?? 7d 5a 20 ?? ?? ?? ae 61 38 ?? ?? ?? ff fe ?? ?? 00 20 ?? ?? ?? 00 91 fe ?? ?? 00 20 ?? ?? ?? 00 91 20 ?? ?? ?? 00 62 60}  //weight: 5, accuracy: Low
        $x_1_2 = "duukukfdcyeffdtm.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBCC_2147845835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBCC!MTB"
        threat_id = "2147845835"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QABEAIAAAIA6AQAABAAEgACACAQAAAAAA8" wide //weight: 1
        $x_1_2 = "GAtBQZAMHAzBQQAEAAIAAOAAA" wide //weight: 1
        $x_1_3 = "___THh________0REREREREREd3d3d3d3d3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBCF_2147845855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBCF!MTB"
        threat_id = "2147845855"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e5 65 56 00 71 00 51 00 42 30 42 30 2c 67 42 30 42 30 42 30 42 30 45 00 42 30 42 30 42 30 42 30 2f 00 2f 00 38 00 42 30 42 30 4c 00 67 00 42 30 42 30 42 30}  //weight: 1, accuracy: High
        $x_1_2 = {30 42 30 42 30 42 30 42 30 42 30 42 30 42 30 42 30 42 30 67 00 42 30 42 30 42 30 42 30 42 30 34 00 66 00 75 00 67 00 34 00 42 30 74 00 42 30 6e 00 4e 00 49 00 62 00 67 00 42 00 e5 65 2c 67 30 00 68 00 56 00 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_FAT_2147845929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.FAT!MTB"
        threat_id = "2147845929"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 06 02 7d ?? 00 00 04 06 03 7d ?? 00 00 04 17 80 ?? 00 00 04 06 fe ?? ?? 00 00 06 73 ?? 00 00 0a 73 ?? 00 00 0a 25 16 6f ?? 00 00 0a 6f ?? 00 00 0a de 03 26 de}  //weight: 3, accuracy: Low
        $x_1_2 = "Xjpclientser.Resource1" wide //weight: 1
        $x_1_3 = "unsdk.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBCG_2147846389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBCG!MTB"
        threat_id = "2147846389"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 13 09 11 09 28 ?? 00 00 0a 72 e0 08 00 70 16 28 ?? 00 00 0a 16 fe 01 13 0a 11 0a 2c 04 09 17 d6 0d 11 08 17 d6 13 08 11 08 11 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_EH_2147846414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.EH!MTB"
        threat_id = "2147846414"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 09 1f 0c 64 61 0d 09 09 1f 19 62 61 0d 09 09 1f 1b 64 61 0d 08 11 04 09 9e 11 04 17 58 13 04 11 04 1f 10 32 da}  //weight: 5, accuracy: High
        $x_1_2 = {57 d4 02 e8 c9 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 31 00 00 00 16 00 00 00 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ER_2147846415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ER!MTB"
        threat_id = "2147846415"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 07 1f 0c 11 07 1f 0c 95 08 1f 0c 95 61 9e 11 07 1f 0d 11 07 1f 0d 95 08 1f 0d 95 61 9e 11 07 1f 0e 11 07 1f 0e 95 08 1f 0e 95 61 9e 11 07 1f 0f 11 07 1f 0f 95 08 1f 0f 95 61}  //weight: 5, accuracy: High
        $x_1_2 = {57 d4 02 e8 c9 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 31 00 00 00 17 00 00 00 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDJ_2147846502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDJ!MTB"
        threat_id = "2147846502"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0e67eff8-0cea-45af-b782-c4abe32c0d52" ascii //weight: 1
        $x_1_2 = "SOCIALCLUBCHECKER" ascii //weight: 1
        $x_1_3 = "Dgppot" ascii //weight: 1
        $x_1_4 = "Wekuolaxonpbn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDM_2147846712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDM!MTB"
        threat_id = "2147846712"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6203583a-ff52-4339-9c90-d377179afd1c" ascii //weight: 1
        $x_1_2 = "RecoReactor" ascii //weight: 1
        $x_1_3 = "jpeeQ0IwxWktqBxo7a.m0isIZ1u0duW28n3D5" ascii //weight: 1
        $x_1_4 = "kSmnWlJPHFVQDBjd1A.TvcOJ1GnlFaOE2lTvU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_T_2147847102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.T!MTB"
        threat_id = "2147847102"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 d4 02 e8 c9 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 31 00 00 00 16 00 00 00 55}  //weight: 2, accuracy: High
        $x_1_2 = "ConfuserEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_GAB_2147847189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.GAB!MTB"
        threat_id = "2147847189"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0d 09 72 ?? 01 00 70 6f ?? 00 00 0a 0b 07 72 ?? 02 00 70 72 ?? 02 00 70 6f ?? 00 00 0a 17 8d ?? 00 00 01 13 05 11 05 16 1f 2c 9d 11 05 6f ?? 00 00 0a 17 9a 0c 08 0a de 1e de 1c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDK_2147847546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDK!MTB"
        threat_id = "2147847546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8dbb708b-a88c-4610-9cf6-73296cda3bd4" ascii //weight: 1
        $x_2_2 = {11 06 11 06 06 94 11 06 08 94 58 20 00 01 00 00 5d 94 0d 11 07 07 04 07 91 09 61 d2 9c 00 07 17 58 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AA_2147847552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AA!MTB"
        threat_id = "2147847552"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0a 03 8e 69 0b 16 0c 07 20 ff 00 00 00 fe 02 16 fe 01 0d 09 2c 1d 00 20 c4 00 00 00 0c 02 08 6f 5b 00 00 0a 00 07 d2 0c 02 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MAAC_2147847722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MAAC!MTB"
        threat_id = "2147847722"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0b 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 06 18 6f 12 00 00 0a 06 6f 13 00 00 0a 02 16 02 8e 69}  //weight: 10, accuracy: Low
        $x_1_2 = "Lnvbke" wide //weight: 1
        $x_1_3 = "daoL" wide //weight: 1
        $x_1_4 = "f7xp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MAAD_2147847786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MAAD!MTB"
        threat_id = "2147847786"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0b 16 0c 2b 13 06 08 06 08 91 07 08 07 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 06 8e 69 32 e7}  //weight: 1, accuracy: High
        $x_1_2 = "1c28daf4-ba03-4ef3-97aa-d217c970f10a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MAAL_2147847921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MAAL!MTB"
        threat_id = "2147847921"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 11 04 06 11 04 1e 5a 1e 6f ?? 00 00 0a 18 28 ?? 00 00 0a 9c 11 04 17 58 13 04 00 17 13 08 2b c8}  //weight: 1, accuracy: Low
        $x_1_2 = {02 72 40 02 00 70 72 01 00 00 70 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARA_2147847940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARA!MTB"
        threat_id = "2147847940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {91 61 b4 9c [0-2] 03 6f 2a 00 00 0a 17 da 33}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARA_2147847940_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARA!MTB"
        threat_id = "2147847940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {61 d1 9d fe ?? ?? ?? 20 ?? ?? ?? ?? 66 20 ?? ?? ?? ?? 58 65 20 ?? ?? ?? ?? 61 66 65 66 20 ?? ?? ?? ?? 63 66 65 59 25 fe}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARA_2147847940_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARA!MTB"
        threat_id = "2147847940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b 1d 1a 5d 16 2d 02 1e 5a 1f 1f 5f 1c 2c fa 63 16 2d ed 61 1a 2c 01}  //weight: 2, accuracy: High
        $x_2_2 = "SelenaGomez.Program" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARA_2147847940_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARA!MTB"
        threat_id = "2147847940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 07 02 07 91 8c ?? ?? ?? 01 03 07 8c ?? ?? ?? 01 03 8e b7 8c ?? ?? ?? 01 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 91 8c ?? ?? ?? 01 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 9c 07 17 d6 0b 07 08 31 c4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARA_2147847940_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARA!MTB"
        threat_id = "2147847940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 20 ff 00 00 00 5f 2b 1d 03 6f ?? ?? ?? 0a 0c 2b 17 08 06 08 06 93 02 7b ?? ?? ?? 04 07 91 04 60 61 d1 9d 2b 03 0b 2b e0 06 17 59 25 0a 16 2f 02 2b 05 2b dd 0a 2b c8}  //weight: 2, accuracy: Low
        $x_2_2 = "Windo.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARA_2147847940_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARA!MTB"
        threat_id = "2147847940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 09 11 08 9a 13 06 09 11 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a b4 6f ?? ?? ?? 0a 11 08 17 d6 13 08 11 08 11 09 8e b7 32 d8}  //weight: 2, accuracy: Low
        $x_2_2 = "funccall22" ascii //weight: 2
        $x_2_3 = "ReD_Security.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARA_2147847940_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARA!MTB"
        threat_id = "2147847940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 02 11 05 91 13 06 03 11 05 07 5d 91 13 07 11 07 08 20 00 01 00 00 5d 58 11 05 58 20 00 01 00 00 5d 13 08 11 06 11 08 19 5a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 13 09 06 11 05 11 09 9c 00 11 05 17 58 13 05 11 05 02 8e 69 fe 04 13 0a 11 0a 2d ac}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARA_2147847940_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARA!MTB"
        threat_id = "2147847940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "<t.me/GhostHackersNetwork>" ascii //weight: 2
        $x_2_2 = "TW96aWxsYS81LjAgK" wide //weight: 2
        $x_2_3 = "U29mdHdhcmVc" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARA_2147847940_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARA!MTB"
        threat_id = "2147847940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "://172.86.96.111:8080/Script.ps1" ascii //weight: 3
        $x_2_2 = "Unblock-File $localPath" ascii //weight: 2
        $x_2_3 = "powershell -ExecutionPolicy Bypass -File $localPath" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARA_2147847940_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARA!MTB"
        threat_id = "2147847940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 08 02 8e 69 5d 1f 17 59 1f 17 58 02 08 02 8e 69 5d 1f 16 58 1f 16 59 91 07 08 07 8e 69 5d 1b 58 1a 58 1f 0b 58 1f 14 59 18 58 18 59 91 61 02 08 20 0f 02 00 00 58 20 0e 02 00 00 59 18 59 18 58 02 8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 16 2c 3c 26 08 19 2c f8 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 3e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARA_2147847940_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARA!MTB"
        threat_id = "2147847940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://xspymain.github.io/teet/VenomDemo.bin" wide //weight: 2
        $x_2_2 = "Client_C_." wide //weight: 2
        $x_1_3 = "shellcode" wide //weight: 1
        $x_2_4 = "DownloadData" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_AsyncRAT_ARA_2147847940_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARA!MTB"
        threat_id = "2147847940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 02 11 06 91 13 07 02 11 06 02 11 06 17 58 91 9c 02 11 06 17 58 11 07 9c 00 11 06 18 58 13 06 11 06 11 04 17 59 fe 04 13 08 11 08 2d d2}  //weight: 2, accuracy: High
        $x_2_2 = {00 11 09 09 59 7e ?? ?? ?? 04 8e 69 5d 13 0a 02 11 09 91 13 0b 08 18 5d 16 fe 01 13 0c 11 0c 39 17 00 00 00 00 06 11 09 11 0b 7e ?? ?? ?? 04 11 0a 91 59 d2 9c 00 38 ?? ?? ?? ?? 00 06 11 09 11 0b 7e ?? ?? ?? 04 11 0a 91 58 d2 9c 00 00 11 09 17 58 13 09 11 09 11 04 fe 04 13 0d 11 0d 2d a0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARA_2147847940_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARA!MTB"
        threat_id = "2147847940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Select * from AntivirusProduct" ascii //weight: 1
        $x_2_2 = "VenomByVenom" ascii //weight: 2
        $x_2_3 = "Paste_bin" ascii //weight: 2
        $x_2_4 = "/c schtasks /create /f /sc onlogon /rl highest /tn" ascii //weight: 2
        $x_2_5 = "masterKey can not be null or empty." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARA_2147847940_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARA!MTB"
        threat_id = "2147847940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JavaUpdate" ascii //weight: 2
        $x_2_2 = "capCreateCaptureWindowA" ascii //weight: 2
        $x_2_3 = "is tampered." wide //weight: 2
        $x_2_4 = "{11111-22222-40001-00001}" wide //weight: 2
        $x_2_5 = "{11111-22222-40001-00002}" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARA_2147847940_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARA!MTB"
        threat_id = "2147847940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$fee4ed48-5732-45aa-9b40-8821cff51e22" ascii //weight: 2
        $x_1_2 = "SELECT * FROM Win32_VideoController" wide //weight: 1
        $x_1_3 = "/c timeout /t 1 && DEL /f" wide //weight: 1
        $x_1_4 = "/c attrib +h" wide //weight: 1
        $x_1_5 = "AntiVM_GPU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_EM_2147848099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.EM!MTB"
        threat_id = "2147848099"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "erp_proje.pdb" ascii //weight: 1
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "yoneticiislem_Load" ascii //weight: 1
        $x_1_4 = "DisableEventWriteToUnderlyingStreamAsyncd" ascii //weight: 1
        $x_1_5 = "get_ConnectionString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AD_2147848132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AD!MTB"
        threat_id = "2147848132"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {32 e7 06 7e ?? 00 00 04 1f 1f 5f 63 8d ?? 00 00 01 0b 7e ?? 00 00 04 13 04 2b 5f 07 11 04 02 11 04 7e ?? 00 00 04 1f 1f 5f 62 6f ?? 00 00 0a 28}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AD_2147848132_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AD!MTB"
        threat_id = "2147848132"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 13 07 09 11 07 d2 6e 1e 11 06 5a 1f 3f 5f 62 60 0d 11 06 17 58 13 06 11 06 1e 32 de 09 69 8d ?? 00 00 01 25 17 73 ?? 00 00 0a 13 04 06 6f ?? 00 00 0a 1f 0d 6a 59 13 05 07 06 11 04 11 05 09 6f}  //weight: 2, accuracy: Low
        $x_2_2 = "KoiVM.Runtime" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MAAN_2147848260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MAAN!MTB"
        threat_id = "2147848260"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0d 2b 1e 08 09 9a fe 06 c9 00 00 06 73 ?? 00 00 0a 07 6f ?? 01 00 06 28 ?? 00 00 0a 26 09 17 58 0d 09 08 8e 69 32 dc}  //weight: 1, accuracy: Low
        $x_1_2 = "AsyncRAT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AB_2147848603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AB!MTB"
        threat_id = "2147848603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 a6 00 00 0a 1f 20 8d 58 00 00 01 25 d0 8e 01 00 04 28 a7 00 00 0a 28 30 01 00 06 28 a8 00 00 0a 72 3e 27 00 70 72 01 00 00 70 6f a9 00 00 0a}  //weight: 2, accuracy: High
        $x_2_2 = {09 11 04 06 11 04 8f 58 00 00 01 72 70 27 00 70 28 ad 00 00 0a a2 11 04 17 58 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AB_2147848603_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AB!MTB"
        threat_id = "2147848603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('" wide //weight: 2
        $x_2_2 = "Out-String" wide //weight: 2
        $x_1_3 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_L_2147848902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.L!MTB"
        threat_id = "2147848902"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "server.Resources.resources" ascii //weight: 2
        $x_2_2 = "ConfusedByAttribute" ascii //weight: 2
        $x_2_3 = {57 d4 02 e8 c9 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 31 00 00 00 16 00 00 00 56 00 00 00 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NC_2147848978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NC!MTB"
        threat_id = "2147848978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 06 51 00 00 06 73 ?? ?? 00 0a 0c 72 ?? ?? 00 70 28 ?? ?? 00 0a 0d 06 08 09 6f ?? ?? 00 0a 7d ?? ?? 00 04}  //weight: 5, accuracy: Low
        $x_1_2 = "Tiffy.Td9ny.resources" ascii //weight: 1
        $x_1_3 = "Econoc7ics" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDN_2147849151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDN!MTB"
        threat_id = "2147849151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "44f7d7bc-bc17-4ab2-ac0c-afcd590259a8" ascii //weight: 1
        $x_1_2 = "BVH876" ascii //weight: 1
        $x_1_3 = "aR3nbf8dQp2feLmk31" ascii //weight: 1
        $x_1_4 = "lSfgApatkdxsVcGcrktoFd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBEQ_2147849502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBEQ!MTB"
        threat_id = "2147849502"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 2c 5d 06 06 72 3f 08 00 70 6f ?? 00 00 0a 72 3f 08 00 70 28 ?? 00 00 0a 58 6f ?? 00 00 0a 28 ?? 00 00 0a 13 08 11 07 11 08 16 11 08 8e 69 6f ?? 00 00 0a 11 07}  //weight: 1, accuracy: Low
        $x_1_2 = "Patrick_Crypter_Stub.Form1.resou" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBER_2147849515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBER!MTB"
        threat_id = "2147849515"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 03 50 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 08 6f ?? 00 00 0a 02 50 16 02 50 8e 69 6f ?? 00 00 0a 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "MSuphMTwOIjOxRUfLIIXpwMGC.MSuphMTwOIjOxRUfLIIXpwMGC" wide //weight: 1
        $x_1_3 = "VeoVTEgmaMAWtwUUXHXNGJkmr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBEZ_2147849736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBEZ!MTB"
        threat_id = "2147849736"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 32 1f 32 73 ?? 00 00 0a 0a 73 ?? 00 00 0a 0b 16 0c 38 ?? 00 00 00 16 0d 38 ?? 00 00 00 06 08 09 07 17 1f 65 6f ?? 00 00 0a 28 ?? 00 00 0a 09 17 58 0d 09 1f 32 32 e6}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 11 41 00 67 00 6e 00 6f 00 73 00 74 00 69 00 63 00 00 c0 02 a3 b1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ASAU_2147849826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ASAU!MTB"
        threat_id = "2147849826"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 00 41 00 41 00 41 00 4b 00 4f 00 4a 00 67 00 41 00 41 00 41 00 42 00 7a 00 67 00 67 00 41 00 41 00 43 00 68 00 4d 00 46 00 63 00 72 00 45 00 41 00 41 00 48 00 42 00 79 00 73 00 51 00 41 00 41 00 63 00 48 00 4f 00 44 00 41 00 41 00 41 00 4b 00 45 00 77 00 59}  //weight: 1, accuracy: High
        $x_1_2 = {67 00 5a 00 55 00 41 00 41 00 41 00 47 00 63 00 34 00 38 00 41 00 41 00 41 00 6f 00 55 00 62 00 35 00 41 00 41 00 41 00 41 00 6f 00 6d 00 4f 00 41 00 59 00 41 00 41 00 41 00 41 00 57 00 4b 00 45 00 67 00 41}  //weight: 1, accuracy: High
        $x_1_3 = {4b 00 45 00 4d 00 41 00 41 00 41 00 59 00 48 00 61 00 6c 00 67 00 6f 00 52 00 41 00 41 00 41 00 42 00 69 00 68 00 42 00 41 00 41 00 41 00 47 00 42 00 32 00 70 00 5a 00 4b 00 45 00 49 00 41 00 41 00 41 00 59 00 6f 00 51}  //weight: 1, accuracy: High
        $x_1_4 = {42 00 41 00 45 00 41 00 41 00 42 00 55 00 41 00 41 00 42 00 45 00 6f 00 53 00 51 00 41 00 41 00 42 00 67 00 6f 00 57 00 43 00 77 00 59 00 53 00 41 00 53 00 69 00 63 00 41 00 41 00 41 00 4b 00 4b 00 45 00 63 00 41 00 41 00 41 00 59 00 36 00 42 00 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NYN_2147850316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NYN!MTB"
        threat_id = "2147850316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 10 00 00 0a 25 26 0b 20 ?? ?? ?? 00 28 ?? ?? ?? 06 25 26 0c 20 ?? ?? ?? 00 28 ?? ?? ?? 06 0d 20 ?? ?? ?? 00 28 ?? ?? ?? 06 20 ?? ?? ?? 00 28 ?? ?? ?? 06 20 ?? ?? ?? 00 28 ?? ?? ?? 06 25 26 28 ?? ?? ?? 0a 13 04 28 ?? ?? ?? 06 25 26 28 ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "BPOIiN877" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBFA_2147850540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBFA!MTB"
        threat_id = "2147850540"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bQAgAEEAbgB0AGkAdgBpAHIAdQBzAFAAcgBvAGQAd" wide //weight: 1
        $x_1_2 = "Crypted.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBFH_2147850541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBFH!MTB"
        threat_id = "2147850541"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 1c 13 05 2b c2 16 0a 1d 13 05 2b bb 04 03 61 1f 31 59 06 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AI_2147850689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AI!MTB"
        threat_id = "2147850689"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 14 14 6f ?? 00 00 0a 26 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {08 09 8e b7 32}  //weight: 2, accuracy: High
        $x_2_3 = {08 17 d6 0c}  //weight: 2, accuracy: High
        $x_2_4 = {08 9a 0b 06 07 18 28}  //weight: 2, accuracy: High
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "ToString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PSRT_2147850755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PSRT!MTB"
        threat_id = "2147850755"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 00 09 28 ?? 00 00 0a 07 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 26 09 72 0b 00 00 70 6f ?? 00 00 0a 26 09 08 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_SP_2147850795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.SP!MTB"
        threat_id = "2147850795"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+joYocqgVkYaNRjKVamtSQ==" wide //weight: 1
        $x_1_2 = "1NZ9gosU7AyEoX7eYIpFOy6VtAxce3NrSP0y5ixwF44=" wide //weight: 1
        $x_1_3 = "56OWfoMsWlFEGLyjtNqHeA==" wide //weight: 1
        $x_1_4 = "3VjDzH1EMRB3c+1x4Jct9Q==" wide //weight: 1
        $x_1_5 = "1B2dvOrw46RbcRqVsKhBng==" wide //weight: 1
        $x_1_6 = "svuqzrGKbvo1S33e/yCN2Q==" wide //weight: 1
        $x_1_7 = "P7u0vzGxqU5DmHDroOxTHQ==" wide //weight: 1
        $x_1_8 = "nUTfoxBT8KqjlQhfYjTbOA==" wide //weight: 1
        $x_1_9 = "xe6xzvrXsMUf5TljHgFcNw==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_A_2147850841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.A!MTB"
        threat_id = "2147850841"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Client.Modules.Keylogger" ascii //weight: 1
        $x_1_2 = "SendKeyLogs" ascii //weight: 1
        $x_1_3 = "Client.Modules.Clipper" ascii //weight: 1
        $x_1_4 = "ClipboardText" ascii //weight: 1
        $x_1_5 = ".Targets.Browsers" ascii //weight: 1
        $x_1_6 = "DetectCreditCardType" ascii //weight: 1
        $x_1_7 = "Discord" ascii //weight: 1
        $x_1_8 = "Passwords.Targets.System" ascii //weight: 1
        $x_1_9 = "GetProfiles" ascii //weight: 1
        $x_1_10 = "uploadfile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PSTD_2147851593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PSTD!MTB"
        threat_id = "2147851593"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 04 00 00 04 72 0d 00 00 70 7e 1c 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 de 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AJ_2147851657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AJ!MTB"
        threat_id = "2147851657"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 d4 02 e8 c9 03 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 31 00 00 00 0c 00 00 00 2b 00 00 00 65}  //weight: 2, accuracy: High
        $x_2_2 = "server.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PSTF_2147851664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PSTF!MTB"
        threat_id = "2147851664"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 80 12 00 00 04 28 10 00 00 0a 26 73 11 00 00 0a 20 e8 03 00 00 20 88 13 00 00 6f 12 00 00 0a 28 0c 00 00 0a 73 f7 01 00 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PSTH_2147851764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PSTH!MTB"
        threat_id = "2147851764"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 5d 00 00 70 0a 06 28 56 00 00 0a 25 26 0b 28 4e 00 00 0a 25 26 07 16 07 8e 69 6f 51 01 00 0a 25 26 0a 28 b5 00 00 0a 25 26}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ASBL_2147851799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ASBL!MTB"
        threat_id = "2147851799"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 17 d6 20 ff 00 00 00 5f 0c 09 11 07 08 91 d6 20 ff 00 00 00 5f 0d 11 07 08 91 13 09 11 07 08 11 07 09 91 9c 11 07 09 11 09 9c 11 06 11 04 11 07 11 07 08 91 11 07 09 91 d6 20 ff 00 00 00 5f 91 06 11 04 91 61 9c 11 04 17 d6 13 04 11 04 11 0c 31 ad}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NSY_2147852198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NSY!MTB"
        threat_id = "2147852198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 17 00 00 01 25 16 72 ?? ?? 00 70 a2 25 17 7e ?? ?? 00 0a a2 25 18 09 a2 25 19 17 8c ?? ?? 00 01 a2 13 04 14 13 05 07 28 ?? ?? 00 0a 72 ?? ?? 00 70 6f ?? ?? 00 0a 72 ?? ?? 00 70 20 ?? ?? 00 00 14 11 05 11 04 74 ?? ?? 00 1b 6f ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Advanced_Calculator.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NSY_2147852198_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NSY!MTB"
        threat_id = "2147852198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1f 6b 28 57 00 00 06 28 ?? ?? 00 0a 28 ?? ?? 00 0a 26 1f 78 28 ?? ?? 00 06 07 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? ?? 00 0a 28 ?? ?? 00 06 26 20 ?? ?? 00 00 28 ?? ?? 00 06 1f 50 28 ?? ?? 00 06 28 ?? ?? 00 06 07 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? ?? 00 0a 28 ?? ?? 00 06 26 1b 8d ?? ?? 00 01 0d 09 16 20 ?? ?? 00 00 28 ?? ?? 00 06 1f 50 28 ?? ?? 00 06 28 ?? ?? 00 06 a2 09 17 28 ?? ?? 00 0a 6f ?? ?? 00 0a a2 09 18 20 ?? ?? 00 00 28 ?? ?? 00 06 a2}  //weight: 5, accuracy: Low
        $x_1_2 = "kbakc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDP_2147852355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDP!MTB"
        threat_id = "2147852355"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 06 6f d8 00 00 0a 1f 20 06 6f d8 00 00 0a 8e 69 1f 20 59 6f d9 00 00 0a 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBHA_2147852447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBHA!MTB"
        threat_id = "2147852447"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VqQ##M####E####//8##Lg#########Q#####" wide //weight: 1
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AK_2147852862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AK!MTB"
        threat_id = "2147852862"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 ff b6 ff 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 9d 00 00 00 5e 04 00 00 4e 01 00 00 d6 13}  //weight: 2, accuracy: High
        $x_2_2 = "C:\\Windows\\Microsoft.NET\\Framework" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AL_2147853400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AL!MTB"
        threat_id = "2147853400"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 d4 02 fc c9 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 33 00 00 00 17 00 00 00 58 00 00 00 a9 00 00 00 4f}  //weight: 2, accuracy: High
        $x_2_2 = "server.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDQ_2147888949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDQ!MTB"
        threat_id = "2147888949"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 0b 00 00 0a 03 28 0c 00 00 0a 6f 0d 00 00 0a 0a 06 6f 0e 00 00 0a 14 14 6f 0f 00 00 0a 26}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBID_2147888950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBID!MTB"
        threat_id = "2147888950"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 07 28 ?? 00 00 0a 04 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 07 6f ?? 00 00 0a 00 73 ?? 00 00 0a 0d 09 08 6f 55 00 00 0a 00 09 05 6f ?? 00 00 0a 00 09 0e 04 6f ?? 00 00 0a 00 09}  //weight: 1, accuracy: Low
        $x_1_2 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 00 0d 49 00 6e 00 76 00 6f 00 6b 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PSWK_2147889429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PSWK!MTB"
        threat_id = "2147889429"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 26 00 00 04 28 ?? 00 00 0a 1e 8d 49 00 00 01 25 d0 3e 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 72 2c 0c 00 70 02 72 32 0c 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 80 25 00 00 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NMM_2147889501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NMM!MTB"
        threat_id = "2147889501"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0c 02 00 28 ?? ?? ?? 0a 80 ?? ?? ?? 04 20 ?? ?? ?? ff 66 20 ?? ?? ?? 00 59 66 fe ?? ?? 00 38 ?? ?? ?? ff 01 20 ?? ?? ?? 00 25 fe ?? ?? 00 26 fe ?? ?? 00 fe ?? ?? 00 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a fe ?? ?? 00 20 ?? ?? ?? 00 fe ?? ?? 00 20 ?? ?? ?? 00 65 65 20 ?? ?? ?? 00 59 fe ?? ?? 00 38 ?? ?? ?? ff 01 20 ?? ?? ?? 00 25 fe ?? ?? 00 26 ?? ?? ?? 00 8e 69 8d ?? ?? ?? 01 20 ?? ?? ?? 00}  //weight: 5, accuracy: Low
        $x_1_2 = "Mains.My.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PSWX_2147890097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PSWX!MTB"
        threat_id = "2147890097"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 3e 0a 00 70 28 ?? 00 00 0a 0a 06 28 ?? 00 00 06 06 28 ?? 00 00 0a 2c 0b 06 28 ?? 00 00 0a 28 ?? 00 00 06 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NST_2147890301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NST!MTB"
        threat_id = "2147890301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 40 05 f9 d2 58 20 ?? ?? ?? 13 61 58 5a 61 20 ?? ?? ?? 7b 58 20 ?? ?? ?? ff 20 ?? ?? ?? 85 20 ?? ?? ?? 50 59 20 ?? ?? ?? cf 20 ?? ?? ?? 93 61 59 20 ?? ?? ?? 35 20 ?? ?? ?? 7d 61 20 ?? ?? ?? eb 66 59 59 66 20 ?? ?? ?? bb 5a 59 59 20 ?? ?? ?? 89 20 ?? ?? ?? af 20 ?? ?? ?? 66 20 ?? ?? ?? 67 61 65 20 ?? ?? ?? 88 66 65 59 5a 66 61 66 58 65 61}  //weight: 5, accuracy: Low
        $x_1_2 = "eUFYmTFePjLfTrXYxnjqwIOkjIbt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NAC_2147890303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NAC!MTB"
        threat_id = "2147890303"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 11 28 0e 02 00 06 28 ?? ?? ?? 06 13 10 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 39 ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff 73 ?? ?? ?? 0a 13 02 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 3a ?? ?? ?? ff 26}  //weight: 5, accuracy: Low
        $x_1_2 = "Qzmmohlg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NSC_2147890498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NSC!MTB"
        threat_id = "2147890498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 01 00 00 70 0a 1f 1c 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 00 00 08 06 07 6f ?? 00 00 0a 00 07 28 ?? 00 00 06}  //weight: 5, accuracy: Low
        $x_1_2 = "kurdishbuild" ascii //weight: 1
        $x_1_3 = "hxca.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NSC_2147890498_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NSC!MTB"
        threat_id = "2147890498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 88 00 00 0a 7e ?? 00 00 04 07 06 6f ?? 00 00 0a 28 ?? 00 00 0a 0d 28 ?? 00 00 0a 09 16 09 8e 69 6f ?? 00 00 0a 28 ?? 00 00 0a 13 04 7e ?? 00 00 04 2c 08 02 11 04 28 ?? 00 00 06 11 04 13 05 de 06}  //weight: 5, accuracy: Low
        $x_1_2 = "Nashwille" ascii //weight: 1
        $x_1_3 = "Net.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AM_2147890531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AM!MTB"
        threat_id = "2147890531"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0e 11 0a 02 11 0a 91 03 11 0a 03}  //weight: 2, accuracy: High
        $x_2_2 = {06 61 d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NAA_2147891168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NAA!MTB"
        threat_id = "2147891168"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 88 48 f6 ff 20 ?? ?? ?? ff 59 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 13 06 12 06 1b 8d ?? ?? ?? 01 25 16 20 ?? ?? ?? 00 8c ?? ?? ?? 01 a2 25 17 72 ?? ?? ?? 70 a2 25 18 72 ?? ?? ?? 70 a2 25 19 20 ?? ?? ?? 00 8c ?? ?? ?? 01 a2 25 1a 1f 5d 8c ?? ?? ?? 01 a2 28 ?? ?? ?? 06 00 11 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 20 ?? ?? ?? 00}  //weight: 5, accuracy: Low
        $x_1_2 = "vtkntsybummgbuek.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ASDW_2147891392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ASDW!MTB"
        threat_id = "2147891392"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 c4 09 00 00 28 ?? 00 00 0a 00 28 ?? 02 00 06 16 fe 01 0a 06 2c 07 16 28}  //weight: 2, accuracy: Low
        $x_1_2 = "[CAPSLOCK: ON]" wide //weight: 1
        $x_1_3 = "[Shift]" wide //weight: 1
        $x_1_4 = "botKiller" wide //weight: 1
        $x_1_5 = "Server Pinged me " wide //weight: 1
        $x_1_6 = "/C choice /C Y /N /D Y /T 1 & Del" wide //weight: 1
        $x_1_7 = "AsyncRAT 0.4" wide //weight: 1
        $x_1_8 = "172.20.10.3" wide //weight: 1
        $x_1_9 = "dXNpbmcgU3lzdGVtOwp1c2luZyBTeXN0ZW0uRGlhZ25vc3RpY3M7CnVzaW5nIFN5c3Rlb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NART_2147891421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NART!MTB"
        threat_id = "2147891421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 0d 00 00 70 28 ?? 00 00 06 0a dd ?? 00 00 00 26 dd ?? 00 00 00 06 2c e6 06 73 ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 07 16 73 ?? 00 00 0a 73 ?? 00 00 0a 0d 09 08 6f ?? 00 00 0a dd ?? 00 00 00 09 39 ?? 00 00 00}  //weight: 5, accuracy: Low
        $x_1_2 = "WindowsFormsApp88" ascii //weight: 1
        $x_1_3 = "Oybii" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AN_2147891425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AN!MTB"
        threat_id = "2147891425"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 00 0a d2 61 d2 61 d2 9c}  //weight: 2, accuracy: High
        $x_1_2 = "GetExportedTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AP_2147892098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AP!MTB"
        threat_id = "2147892098"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 94 02 28 c9 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 31 00 00 00 17 00 00 00 58 00 00 00 9e}  //weight: 2, accuracy: High
        $x_2_2 = "server.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AQ_2147892103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AQ!MTB"
        threat_id = "2147892103"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[DefaultInstall]" wide //weight: 2
        $x_2_2 = "CustomDestination=CustInstDestSectionAllUsers" wide //weight: 2
        $x_2_3 = "RunPreSetupCommands=RunPreSetupCommandsSection" wide //weight: 2
        $x_2_4 = "[RunPreSetupCommandsSection]" wide //weight: 2
        $x_2_5 = "taskkill /IM cmstp.exe /F" wide //weight: 2
        $x_2_6 = "[CustInstDestSectionAllUsers]" wide //weight: 2
        $x_2_7 = "49000,49001=AllUSer_LDIDSection, 7" wide //weight: 2
        $x_2_8 = "[AllUSer_LDIDSection]" wide //weight: 2
        $x_2_9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE" wide //weight: 2
        $x_2_10 = "%UnexpectedError%" wide //weight: 2
        $x_2_11 = "ProfileInstallPath" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NSN_2147892110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NSN!MTB"
        threat_id = "2147892110"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5f e0 95 11 07 25 1a d3 58 13 07 4b 61 20 ?? ?? ?? 3d 58 9e 20 ?? ?? ?? b8 38 ?? ?? ?? ff 11 14 1e 11 14 1e 95 11 15 1e 95 58}  //weight: 5, accuracy: Low
        $x_1_2 = "rkxkkflfzhejxsp.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBJL_2147892207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBJL!MTB"
        threat_id = "2147892207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 e1 31 06 70 a2 25 17 72 e7 31 06 70 a2 0a 06 16 9a 06 17 9a 28 ?? 00 00 0a 72 ed 31 06 70 15 16}  //weight: 1, accuracy: Low
        $x_1_2 = {72 f3 31 06 70 15 16 28 ?? 00 00 0a 0b 16 0c 2b 2d 07 08 9a 0d 06 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBJL_2147892207_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBJL!MTB"
        threat_id = "2147892207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {36 00 49 00 67 00 33 00 41 00 51 00 43 00 49 00 4e 00 77 00 45 00 41 00 68 00 72 00 5a 00 6b 00 33 00 45 00 57 00 57 00 30 00 6a 00 43 00 66 00 75 00 52 00 4a 00 47 00 39 00 54 00 52 00 52 00 31}  //weight: 10, accuracy: High
        $x_10_2 = {36 00 49 00 67 00 31 00 41 00 51 00 43 00 49 00 4e 00 51 00 45 00 41 00 48 00 62 00 4e 00 6e 00 76 00 38 00 39 00 59 00 70 00 6e 00 64 00 42 00 49 00 59 00 2b 00 57 00 61 00 61 00 4b 00 62 00 30}  //weight: 10, accuracy: High
        $x_1_3 = "NativeCaller" ascii //weight: 1
        $x_1_4 = "Shellcode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_AsyncRAT_NRT_2147892295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NRT!MTB"
        threat_id = "2147892295"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 09 00 00 06 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 0a 72 ?? ?? ?? 70 06 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 26 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "crypter2" ascii //weight: 1
        $x_1_3 = "rnaudar*at2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NA_2147892296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NA!MTB"
        threat_id = "2147892296"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {7d 01 00 00 04 08 17 58 0c 2b 09 06 03 08 94 6f ?? 00 00 0a 08 17}  //weight: 3, accuracy: Low
        $x_3_2 = {28 01 00 00 2b 28 ?? 00 00 2b 0a 1a 06 6f ?? 00 00 0a 59 0b}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NA_2147892296_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NA!MTB"
        threat_id = "2147892296"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 11 0d 16 11 0b 6f ?? 00 00 0a 25 26 26 11 0a 11 0d 16 11 0b 11 0c 16 6f ?? 00 00 0a 13 0f 7e ?? 00 00 04 11 0c 16 11 0f 6f ?? 00 00 0a 11 0e 11 0b 58 13 0e 11 0e 11 0b 58 6a 06 6f ?? 00 00 0a 25 26 32 bb}  //weight: 5, accuracy: Low
        $x_1_2 = "HYYHJIOpLKm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ASDX_2147892389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ASDX!MTB"
        threat_id = "2147892389"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 11 0a 11 0d 91 61 b4 9c 11 0d 03 6f ?? 00 00 0a 17 da 33 05 16 13 0d 2b 06 11 0d 17 d6 13 0d 11 0f 17 d6 13 0f 11 0f 11 10 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBJM_2147892398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBJM!MTB"
        threat_id = "2147892398"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0a 11 0f 02 11 0f 91 11 0d 61 11 09 11 07 91 61 b4 9c 11 07 03 6f ?? 00 00 0a 17 da 33 05}  //weight: 1, accuracy: Low
        $x_1_2 = {76 00 69 00 56 00 76 00 53 00 66 00 74 00 62 00 73 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBJM_2147892398_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBJM!MTB"
        threat_id = "2147892398"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b db 17 2c 53 1f 32 28}  //weight: 1, accuracy: High
        $x_1_2 = {dd 00 d5 00 4f 00 cf 00 57 00 41 00 83 00 e8 00 ec 00 d6}  //weight: 1, accuracy: High
        $x_1_3 = "D2X87H4ybuPT5a4P49sL0i" ascii //weight: 1
        $x_1_4 = "$05a05012-33c1-4318-9140-df46dddc3bad" ascii //weight: 1
        $x_1_5 = "Services.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AMMB_2147892939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AMMB!MTB"
        threat_id = "2147892939"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 17 59 91 07 08 07 8e 69 5d 1f ?? 58 1b 58 1f 39 59 17 59 91 61 03 08 20 ?? ?? ?? ?? 58 20 ?? ?? ?? ?? 59 03 8e 69 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AMMB_2147892939_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AMMB!MTB"
        threat_id = "2147892939"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 09 02 7b ?? 01 00 04 09 02 7b ?? 01 00 04 8e 69 5d 91 9e 09 17 58 0d 09 20 00 01 00 00 32 e0}  //weight: 5, accuracy: Low
        $x_5_2 = {11 05 06 11 04 94 58 08 11 04 94 58 20 00 01 00 00 5d 13 05 06 11 04 94 13 06 06 11 04 06 11 05 94 9e 06 11 05 11 06 9e 11 04 17 58 13 04 11 04 20 00 01 00 00 32 c9}  //weight: 5, accuracy: High
        $x_1_3 = "ProcessHacker.exe" ascii //weight: 1
        $x_1_4 = "exe.rekcaHssecorP" ascii //weight: 1
        $x_1_5 = "Select * from AntivirusProduct" ascii //weight: 1
        $x_1_6 = "tcudorPsurivitnA morf * tceleS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_AsyncRAT_AMAA_2147892940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AMAA!MTB"
        threat_id = "2147892940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 16 20 00 10 00 00 28 ?? 00 00 06 0d 09 16 31 09 08 07 16 09 28 ?? 00 00 06 09 16 30 e1}  //weight: 5, accuracy: Low
        $x_1_2 = "injector.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AMAA_2147892940_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AMAA!MTB"
        threat_id = "2147892940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 0d 07 16 08 16 1f 10 28 ?? 00 00 0a 00 07 1f 10 09 16 1f 10 28 ?? 00 00 0a 00 73 ?? 00 00 0a 08 09 6f ?? 00 00 0a 13 04 04 73 ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 00 11 05 11 04 16 73 ?? 00 00 0a 13 07 00 11 07 11 06 6f ?? 00 00 0a 00 00 de 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_EC_2147893053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.EC!MTB"
        threat_id = "2147893053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AsyncRAT 0.4" ascii //weight: 1
        $x_1_2 = "dqqitdai.b0p" ascii //weight: 1
        $x_1_3 = "Connected!" ascii //weight: 1
        $x_1_4 = "Inject" ascii //weight: 1
        $x_1_5 = "/C choice /C Y /N /D Y /T 1 & Del" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ASEW_2147893252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ASEW!MTB"
        threat_id = "2147893252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3hT4ejw1aNTSVmD+uD3sfkd6dFqNfrdgT" wide //weight: 1
        $x_1_2 = "dyk5oadFPgAfbMU38ToHaX5S9hcPM2eRNfc" wide //weight: 1
        $x_1_3 = "VYsy~og98Vlenbofzox$oro" wide //weight: 1
        $x_1_4 = "Yel~}kxoVIfkyyoyVorolcfoVYboffVEzodVieggkdn" wide //weight: 1
        $x_1_5 = "C:\\My Pictures.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_SPT_2147893934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.SPT!MTB"
        threat_id = "2147893934"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 07 08 91 20 ?? ?? ?? 00 59 d2 9c 00 08 17 58 0c 08 07 8e 69 fe 04 0d 09 2d e3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AR_2147893942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AR!MTB"
        threat_id = "2147893942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 1d 20 31 01 00 00 9d 06 1c 20 f5 26 00 00 9d 06 19 20 b8 38 00 00 9d 06 17 20 6b 19 00 00 9d 06 16 20 b9 03 00 00 9d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AR_2147893942_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AR!MTB"
        threat_id = "2147893942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 bd a2 3f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 62 00 00 00 1f 00 00 00 39 00 00 00 dd}  //weight: 2, accuracy: High
        $x_1_2 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_3 = "MD5CryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_SPDD_2147894267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.SPDD!MTB"
        threat_id = "2147894267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d 24 00 00 01 0a 02 28 ?? ?? ?? 0a 0b 28 ?? ?? ?? 0a 0c 08 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 06 6f ?? ?? ?? 0a 08 08 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d 07 73 1e 00 00 0a 13 04}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AS_2147894580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AS!MTB"
        threat_id = "2147894580"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 fd a2 ff 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 62 00 00 00 1f 00 00 00 39 00 00 00 dd}  //weight: 2, accuracy: High
        $x_1_2 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_3 = "MD5CryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ASFO_2147895492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ASFO!MTB"
        threat_id = "2147895492"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JTGSCVDINFZSA4DSN5TX~YLN~%RWC3TON52CAYTF~%ZHK3RANFXCARCPKMQG233~MUXA2DIK~Q" wide //weight: 1
        $x_1_2 = {4f 00 47 00 41 00 58 00 44 00 41 00 4c 00 52 00 51 00 46 00 51 00 51 00 7e 00 47 00 35 00 4c 00 4d 00 4f 00 52 00 32 00 58 00 7e 00 5a 00 4a 00 35 00 4e 00 5a 00 53 00 58 00 4b 00 35 00 44 00 53 00 4d 00 46 00 57 00 43 00 59 00 49 00 43 00 51 00 4f 00 56 00 52 00 47 00 59 00 32 00 4c 00 44 00 4a 00 4e 00 53 00 58 00 53 00 56 00 44 00 50 00 4e 00 4e 00 53 00 57 00 34 00 50 00 4c 00 43 00 47 00 34 00 33 00 57 00 43 00 4e 00 4c 00 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ASFP_2147895493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ASFP!MTB"
        threat_id = "2147895493"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 2b 17 06 08 06 08 91 07 08 07 8e 69 5d 91 61 d2 9c 08 28 ?? 00 00 06 58 0c 08 06 8e 69 32 e3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBEU_2147896060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBEU!MTB"
        threat_id = "2147896060"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hjfdfhfgfadffddcdffffskhj" ascii //weight: 1
        $x_1_2 = "sgfhjffffgdrfhdfdfhffadfsfsscfgdb" ascii //weight: 1
        $x_1_3 = "gdfgd2dfsfvfgdfdj" ascii //weight: 1
        $x_1_4 = "fghhfgsffrfdfdfffdfdshfdsdfh" ascii //weight: 1
        $x_1_5 = "cfffdadfdrsfsshdkfffgh" ascii //weight: 1
        $x_1_6 = "RijndaelManaged" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAA_2147896423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAA!MTB"
        threat_id = "2147896423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bndf.exe" wide //weight: 1
        $x_1_2 = "PasswordDeriveBytes" ascii //weight: 1
        $x_1_3 = "Decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ABO_2147896515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ABO!MTB"
        threat_id = "2147896515"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {73 42 00 00 0a 0a 06 28 43 00 00 0a 03 50 6f 44 00 00 0a 6f 45 00 00 0a 0b 73 46 00 00 0a 0c 08 07 6f 47 00 00 0a 08 28 62 00 00 06 6f 48 00 00 0a 08 6f 49 00 00 0a 02 50 28 63 00 00 06 02 50 8e 69 6f 4a 00 00 0a 2a}  //weight: 4, accuracy: High
        $x_1_2 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ABBK_2147896522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ABBK!MTB"
        threat_id = "2147896522"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 13 05 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 06 72 ?? ?? ?? 70 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 00 00 de 0d 11 04 2c 08 11 04 6f ?? ?? ?? 0a 00 dc}  //weight: 2, accuracy: Low
        $x_1_2 = "AsyncCC.Properties.Resources" wide //weight: 1
        $x_1_3 = "Multichain_NFT_Sniper_Bot" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ABQ_2147896628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ABQ!MTB"
        threat_id = "2147896628"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 2c 07 08 6f 19 ?? ?? 0a 00 dc 2a 55 00 00 28 3a ?? ?? 0a 7e 1c ?? ?? 04 6f 3b ?? ?? 0a 72 cd ?? ?? 70 28 3c ?? ?? 0a 28 3d ?? ?? 0a 6f 3e ?? ?? 0a 0a 06 6f 3f ?? ?? 0a 0b 73 40 ?? ?? 0a 0c 00 07 08 6f 41 ?? ?? 0a 00 08 6f 42 ?? ?? 0a 80 1b ?? ?? 04 00 de 0b}  //weight: 5, accuracy: Low
        $x_1_2 = "GetResponse" ascii //weight: 1
        $x_1_3 = "GetResponseStream" ascii //weight: 1
        $x_1_4 = "GetExportedTypes" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_SPQN_2147896639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.SPQN!MTB"
        threat_id = "2147896639"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 06 03 06 91 1f 7b 61 d2 9c 06 17 58 0a 06 03 8e 69 32 ec}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_DL_2147897042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.DL!MTB"
        threat_id = "2147897042"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 7e 07 0f 00 04 02 07 6f 63 00 00 0a 7e aa 0e 00 04 07 7e aa 0e 00 04 8e 69 5d 91 61 28 6c 2f 00 06 28 71 2f 00 06 26 07 17 58 0b 07 02 6f 64 00 00 0a 32 c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PSPW_2147897145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PSPW!MTB"
        threat_id = "2147897145"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 5f 00 00 0a 73 ?? ?? ?? 0a 7d 0b 00 00 04 02 6f ?? ?? ?? 06 72 ?? ?? ?? 70 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 02 7b 0b 00 00 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 02 20 e8 03 00 00 28 ?? ?? ?? 0a 7d 0e 00 00 04 02 28 16 00 00 06 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NL_2147898265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NL!MTB"
        threat_id = "2147898265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 06 8e 69 33 02 16 0d 08 11 04 07 11 04 91 06 09 93 ?? ?? ?? ?? ?? 61 d2 9c 09 17 58 0d 11 04 17 58 13 04 11 04 07 8e 69 32 d5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_NL_2147898265_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NL!MTB"
        threat_id = "2147898265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 19 00 00 00 38 59 f2 ff ff 00 02 7b 1f 00 00 04 20 93 ?? ?? ?? 20 01 00 00 00 63 20 9d ?? ?? ?? 61 7e 47 01 00 04 7b 2e 01 00 04 61 7e ae 03 00 04}  //weight: 1, accuracy: Low
        $x_1_2 = {20 75 00 00 00 fe 0e 01 00 38 9b fb ff ff 00 02 11 00 20 82 ?? ?? ?? 20 ac d2 88 c5 61 20 9c ef 18 25 61 7e 47 ?? ?? ?? 7b 7c 01 00 04 61 7e ae 03 00 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PTDJ_2147898315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PTDJ!MTB"
        threat_id = "2147898315"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 04 00 00 0a 0b 07 72 01 00 00 70 6f 05 00 00 0a 0c 08 28 ?? 00 00 0a 0a 06 14 28 ?? 00 00 0a 2c 56}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDR_2147898331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDR!MTB"
        threat_id = "2147898331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Apollo Justice Script Editor" ascii //weight: 1
        $x_1_2 = "Beds-Protector" ascii //weight: 1
        $x_1_3 = "Stop Trying To Unpack the tool!" ascii //weight: 1
        $x_1_4 = "BabelObfuscator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AU_2147898450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AU!MTB"
        threat_id = "2147898450"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AFkAdwBCAHQAQQBHAFEAQQBMAGcAQgBsAEEASABnAEEAWgBRAEEAPQ==" wide //weight: 2
        $x_2_2 = "AEwAdwBCAGoAQQBDAEEAQQBZAHcAQgB2AEEASABBAEEAZQBRAEEAZwBBA" wide //weight: 2
        $x_2_3 = "gBnAEEAZwBBAEgAQQBBAGEAUQBCAHUAQQBHAGMAQQBJAEEAQQB4AEEAQwA0AEEATQBRAEEAdQBBAEQARQBBAEwAZwBBAHgAQQBBAD0APQ==" wide //weight: 2
        $x_2_4 = "AFEAdwBBADYAQQBGAHcAQQBWAHcAQgBwAEEARwA0AEEAWgBBAEIAdgBBAEgAYwBBAGMAdwBCAGMAQQBFADAAQQBhAFEAQgBqAEEASABJAEEAYgB3" wide //weight: 2
        $x_2_5 = "AEIAegBBAEcAOABBAFoAZwBCADAAQQBDADQAQQBUAGcAQgBGAEEARgBRAEEAWABBAEIARwBBAEgASQBBAFkAUQBCAHQAQQBHAFUAQQBkAHcAQgB2AEE" wide //weight: 2
        $x_2_6 = "ASABJAEEAYQB3AEIAYwB" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDS_2147898456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDS!MTB"
        threat_id = "2147898456"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 6f 1c 00 00 0a 5d 28 ?? ?? ?? ?? 61 d2 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDT_2147898611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDT!MTB"
        threat_id = "2147898611"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 0e 00 00 04 7e 0a 00 00 04 6f 84 00 00 06 28 17 00 00 0a 73 19 00 00 0a 80 0c 00 00 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MBFO_2147898817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MBFO!MTB"
        threat_id = "2147898817"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 06 06 6f ?? 01 00 0a 25 26 1f 10 6a 59 17 6a 58 d4 8d 19 00 00 01 13 07 11 06 11 07 16 11 07 8e 69}  //weight: 1, accuracy: Low
        $x_1_2 = {de 00 20 88 13 00 00 28 ?? 00 00 0a 2b d3}  //weight: 1, accuracy: Low
        $x_1_3 = {41 73 79 6e 63 43 6c 69 65 6e 74 00 41 73 79 6e 63 43 6c 69 65 6e 74 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = "CO_VerifyHash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAB_2147898989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAB!MTB"
        threat_id = "2147898989"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 00 11 02 11 00 11 02 93 20 ?? 00 00 00 61 02 61 d1 9d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AMBA_2147900278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AMBA!MTB"
        threat_id = "2147900278"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 07 08 16 73 ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 09 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 de 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_LN_2147900616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.LN!MTB"
        threat_id = "2147900616"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 05 02 11 05 91 07 61 08 09 91 61 b4 9c 09 03 ?? ?? ?? ?? ?? 17 da 33 04 16 0d 2b 04 09 17 d6 0d 11 05 17 d6 13 05 11 05 11 06 31 d1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PTFR_2147900767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PTFR!MTB"
        threat_id = "2147900767"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 4a 00 00 0a 6f 4b 00 00 0a 72 cf 00 00 70 72 99 00 00 70 6f 4c 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PTFW_2147900828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PTFW!MTB"
        threat_id = "2147900828"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 79 25 00 70 28 ?? 01 00 06 08 75 0e 00 00 1b 28 ?? 01 00 06 a2 1d 13 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PTGG_2147900867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PTGG!MTB"
        threat_id = "2147900867"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 ba 02 00 70 28 ?? 00 00 0a 72 be 02 00 70 72 c2 02 00 70 6f 7c 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 a2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PTGH_2147900868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PTGH!MTB"
        threat_id = "2147900868"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fe 0c 03 00 28 ?? 00 00 0a fe 0c 02 00 6f ac 01 00 06 6f 30 00 00 0a 7d 35 01 00 04 fe 0c 03 00 fe 0c 02 00 6f a8 01 00 06 72 cb 00 00 70}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PTEF_2147901147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PTEF!MTB"
        threat_id = "2147901147"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {38 ed fd ff ff 12 01 28 ?? 00 00 0a 28 ?? 03 00 06 13 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_MVA_2147902434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MVA!MTB"
        threat_id = "2147902434"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ClientAny.exe" ascii //weight: 2
        $x_2_2 = "VenomRATByVenom" ascii //weight: 2
        $x_1_3 = "RunAntiAnalysis" ascii //weight: 1
        $x_1_4 = "/c schtasks /create /f /sc onlogon /ru system /rl highest /tn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_AsyncRAT_MVB_2147902435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.MVB!MTB"
        threat_id = "2147902435"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EmptyClean.exe" ascii //weight: 2
        $x_1_2 = "WriteLine" ascii //weight: 1
        $x_1_3 = "MD5Decrypt" ascii //weight: 1
        $x_1_4 = "ee40f0eb-7fc1-4dad-ac1f-1cca8f8702fd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_AsyncRAT_NB_2147902551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.NB!MTB"
        threat_id = "2147902551"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AsyncRAT | Disbale Defender" ascii //weight: 1
        $x_1_2 = "Miner XMR" ascii //weight: 1
        $x_1_3 = "Recovery Password" ascii //weight: 1
        $x_1_4 = "Keylogger" ascii //weight: 1
        $x_1_5 = "Plugins\\Wallets.dll" ascii //weight: 1
        $x_1_6 = "Cmd / Powershell" ascii //weight: 1
        $x_1_7 = "txtWallet" ascii //weight: 1
        $x_1_8 = "HKEY_CURRENT_USER\\SOFTWARE\\AsyncRAT" ascii //weight: 1
        $x_1_9 = "//127.0.0.1/payload.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAD_2147902683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAD!MTB"
        threat_id = "2147902683"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 06 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 07 11 07 11 05 16 11 05 8e 69 6f ?? 00 00 0a 11 07 6f ?? 00 00 0a dd ?? 00 00 00 11 07 39 ?? 00 00 00 11 07 6f ?? 00 00 0a dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAE_2147902784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAE!MTB"
        threat_id = "2147902784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GJQVmthUElIe" wide //weight: 1
        $x_1_2 = "ibeERMRERFvFQ" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_CK_2147902967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.CK!MTB"
        threat_id = "2147902967"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rentry.co/MuckSoft/raw" wide //weight: 1
        $x_1_2 = "zip.org/a/7zr.exe" wide //weight: 1
        $x_1_3 = "psomaliMUSTAFA681!!" wide //weight: 1
        $x_1_4 = "ProgramData\\MicrosoftTool\\current\\Microsoft.exe" wide //weight: 1
        $x_1_5 = "ProgramData\\7zr.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PTJA_2147903207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PTJA!MTB"
        threat_id = "2147903207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 16 08 28 9f 00 00 0a 28 9b 00 00 0a 11 04 16 11 04 8e 69 6f e0 00 00 0a 13 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDU_2147903220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDU!MTB"
        threat_id = "2147903220"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 26 69 6f ?? ?? ?? ?? 25 26 13 04 09}  //weight: 2, accuracy: Low
        $x_1_2 = "Windows PowerShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAF_2147903531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAF!MTB"
        threat_id = "2147903531"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 91 61 03 08 20 ?? 10 00 00 58 20 ?? 10 00 00 59 03 8e 69 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAG_2147903732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAG!MTB"
        threat_id = "2147903732"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 91 61 04 08 20 ?? 10 00 00 58 20 ?? 10 00 00 59 04 8e 69 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AW_2147904622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AW!MTB"
        threat_id = "2147904622"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 11 07 72 ?? ?? 00 70 28 ?? 00 00 0a 28 ?? 00 00 2b 6f ?? 00 00 0a 26 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDV_2147905009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDV!MTB"
        threat_id = "2147905009"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Htility Hiew" ascii //weight: 1
        $x_1_2 = "VHD Image" ascii //weight: 1
        $x_1_3 = "server1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDW_2147905010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDW!MTB"
        threat_id = "2147905010"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 01 00 00 2b 72 01 00 00 70 6f 04 00 00 0a 14 14}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_HQAA_2147905053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.HQAA!MTB"
        threat_id = "2147905053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 25 2d 17 26 7e ?? 00 00 04 fe ?? ?? 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 0a 00 28 ?? 00 00 0a 06 6f ?? 00 00 0a 0b 2b 00 07 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAH_2147906220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAH!MTB"
        threat_id = "2147906220"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 05 11 05 14 72 ?? 00 00 70 17 8d ?? 00 00 01 13 06 11 06 16 28 ?? 00 00 0a 03 6f ?? 00 00 0a a2 11 06 14 14 14 28 ?? 00 00 0a 74 ?? 00 00 1b 0c 2b 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDY_2147906497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDY!MTB"
        threat_id = "2147906497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5d 94 13 0a 11 07 11 08 03 11 08 91 11 0a 61 28 ?? ?? ?? ?? 9c 11 08 17 58 13 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AZ_2147906531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AZ!MTB"
        threat_id = "2147906531"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 09 06 09 91 08 09 08 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d2 9c 09 17 58 0d 09 06 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AX_2147906569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AX!MTB"
        threat_id = "2147906569"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 25 16 72 ?? ?? 00 70 a2 25 17 72 ?? ?? 00 70 a2 25 18 72 ?? ?? 00 70 a2 25 19 72 ?? ?? 00 70 a2 25 1a 72 ?? ?? 00 70 a2 25 1b}  //weight: 2, accuracy: Low
        $x_2_2 = "{0}{1}:{2}/{3}{4}." wide //weight: 2
        $x_2_3 = "/{5}{6}/{7}{8}{9}" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAK_2147907486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAK!MTB"
        threat_id = "2147907486"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 5d 1f ?? 58 1f ?? 58 1f ?? 59 91 61 06 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BB_2147907989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BB!MTB"
        threat_id = "2147907989"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 13 08 07 11 08 6f 13 00 11 07 28 ?? 00 00 0a 72 ?? 01 00 70 6f ?? 00 00 0a 6f}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 0c 08 06 16 06 8e 69 6f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARAQ_2147908239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARAQ!MTB"
        threat_id = "2147908239"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "/hatthgola.vmp.dll" ascii //weight: 8
        $x_2_2 = "txt.cnysa/19902:03.991.21.402//:ptth" wide //weight: 2
        $x_2_3 = "SCHtAsKs.EXe" wide //weight: 2
        $x_2_4 = "/create /tn" wide //weight: 2
        $x_2_5 = "%APpDAta%" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            ((1 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_AsyncRAT_RDZ_2147908447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDZ!MTB"
        threat_id = "2147908447"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 28 12 00 00 06 28 14 00 00 06 6f 1a 00 00 0a 02 16 02 8e 69 6f 1b 00 00 0a 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BC_2147909819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BC!MTB"
        threat_id = "2147909819"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 1f 10 28 ?? 00 00 0a 03 07 6f ?? 00 00 0a 28 ?? 00 00 0a 61 28 ?? 00 00 0a 13 04 12 04 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BD_2147909821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BD!MTB"
        threat_id = "2147909821"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 1f 3c 28 ?? 00 00 06 13 05 03 11 05 1f 32 58 18 58 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAL_2147910713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAL!MTB"
        threat_id = "2147910713"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 00 6f 00 46 00 51 00 41 00 41 00 43 00 71 00 49 00 49 00 48 00 77 00 77 00 6f 00 45}  //weight: 1, accuracy: High
        $x_1_2 = "BzEAAACgoGbxEAA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARAZ_2147912548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARAZ!MTB"
        threat_id = "2147912548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vbMkS7Zlefv" ascii //weight: 2
        $x_2_2 = "{1a03e440-3297-4844-8a84-ca371edd3f90}" ascii //weight: 2
        $x_2_3 = "GetExecutingAssembly" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARAZ_2147912548_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARAZ!MTB"
        threat_id = "2147912548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 16 13 04 2b 33 7e ?? ?? ?? 04 11 04 6f ?? ?? ?? 0a 09 33 1e 06 7e ?? ?? ?? 04 11 04 6f ?? ?? ?? 0a 13 05 12 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 2b 14 11 04 17 58 13 04 11 04 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 32 bf 08 17 58 0c 08 07 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARAZ_2147912548_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARAZ!MTB"
        threat_id = "2147912548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "xuZiTqgdduBxisxUPMF0G7A3kj7Sx8WL" ascii //weight: 2
        $x_2_2 = {00 06 07 02 07 91 28 ?? ?? ?? 0a 9d 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e5}  //weight: 2, accuracy: Low
        $x_2_3 = ".resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAP_2147913671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAP!MTB"
        threat_id = "2147913671"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 19 13 0a}  //weight: 1, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ABW_2147914874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ABW!MTB"
        threat_id = "2147914874"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HiddenRDP_Load" ascii //weight: 1
        $x_1_2 = "Ransomware_Load" ascii //weight: 1
        $x_1_3 = "Keyloaggar_Load" ascii //weight: 1
        $x_1_4 = "RemoteApp_Load" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BE_2147915121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BE!MTB"
        threat_id = "2147915121"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {16 13 13 2b 3e 00 11 0a 11 13 28 16 00 00 0a 13 07 11 07 11 13 58 13 07 11 07 11 05 11 13 28 06 00 00 06 13 07 11 07 28 17 00 00 0a 13 09 11 09 16 11 0a 11 13 1a 28 15 00 00 0a 00 00 11 13 1a 58 13 13 11 13 11 06 fe 05 13 14 11 14 2d b6}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BF_2147915198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BF!MTB"
        threat_id = "2147915198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 fe 0e 03 00 fe 0c 03 00 14 14 14 28}  //weight: 2, accuracy: High
        $x_4_2 = {0a 0d 09 02 16 02 8e 69 6f}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BF_2147915198_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BF!MTB"
        threat_id = "2147915198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 09 11 05 94 58 11 04 11 05 94 58 72 5f 02 00 70 28 43 00 00 0a 5d 13 06 09 11 05 94 13 0b 09 11 05 09 11 06 94 9e 09 11 06 11 0b 9e 11 05 17 58 13 05 11 05 72 5f 02 00 70 28 43 00 00 0a 32 be}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BG_2147915212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BG!MTB"
        threat_id = "2147915212"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 0d 09 14 14 14}  //weight: 2, accuracy: High
        $x_4_2 = {06 0d 09 02 16 02 8e 69 6f}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BG_2147915212_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BG!MTB"
        threat_id = "2147915212"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {11 05 11 0a 75 6a 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 74 6a 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f 42 02 00 0a 26}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BH_2147915711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BH!MTB"
        threat_id = "2147915711"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 11 07 72 ?? 00 00 70 28 ?? 00 00 06 28 ?? 00 00 2b 28 ?? 00 00 06 26 20 00 00 00 00 7e}  //weight: 4, accuracy: Low
        $x_2_2 = {11 00 11 01 16 1a 28 ?? 00 00 06 26 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BJ_2147917665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BJ!MTB"
        threat_id = "2147917665"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 02 17 59 6f ?? 00 00 0a 06 7b ?? 00 00 04 8e 69 58 0c 07 02 6f ?? 00 00 0a 08 59 0d 06 7b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDAA_2147917859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDAA!MTB"
        threat_id = "2147917859"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 06 8f 24 00 00 01 25 71 24 00 00 01 1f 32 59 d2 81 24 00 00 01 00 06 17 58 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDAB_2147917981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDAB!MTB"
        threat_id = "2147917981"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "27c5f22f-9f98-4901-9b33-cdf308de6339" ascii //weight: 2
        $x_1_2 = "ConsoleApplication1" ascii //weight: 1
        $x_1_3 = "wafaasex" ascii //weight: 1
        $x_1_4 = "vcxrterrer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_GNK_2147918577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.GNK!MTB"
        threat_id = "2147918577"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 32 1d 11 0c 5f 91 13 19 11 19 19 62 11 19 1b 63 60 d2 13 19 11 06 11 0c 11 06 11 0c 91 11 19 61 d2 9c 11 0c 17 58 13 0c 11 0c 11 07 32 d1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BM_2147918683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BM!MTB"
        threat_id = "2147918683"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 05 11 09 08 11 09 91 11 04 61 09 11 06 91 61 28}  //weight: 4, accuracy: High
        $x_2_2 = {08 8e 69 17 59 91 1f ?? 61 13 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDAC_2147919015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDAC!MTB"
        threat_id = "2147919015"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 08 17 73 1f 00 00 0a 13 04 11 04 06 16 06 8e 69 6f 20 00 00 0a 09 6f 21 00 00 0a 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAM_2147919423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAM!MTB"
        threat_id = "2147919423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 5d 91 61 d2 9c 00 fe 09 06 00 71 ?? 00 00 01 20 01 00 00 00 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BO_2147919875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BO!MTB"
        threat_id = "2147919875"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 06 94 d6 20 00 01 00 00 5d 94 13 10 02 06 17 da 17 6f ?? 00 00 0a 6f ?? 00 00 0a 16 93 13 0e 11 0e 28 ?? 00 00 0a 13 0f 11 0f 11 10 61 13 0d 08 11 0d 28 ?? 00 00 0a 6f ?? 00 00 0a 26 12 00 28 ?? 00 00 0a 06 17 da 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BP_2147920662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BP!MTB"
        threat_id = "2147920662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0d 09 08 17 73 ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 05}  //weight: 4, accuracy: Low
        $x_2_2 = {09 17 58 0d 09 08 8e 69 32}  //weight: 2, accuracy: High
        $x_1_3 = "CreateDelegate" ascii //weight: 1
        $x_1_4 = "DynamicInvoke" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PHW_2147920668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PHW!MTB"
        threat_id = "2147920668"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "xspymain.github.io" ascii //weight: 2
        $x_1_2 = "InvokeRandomMethod" ascii //weight: 1
        $x_1_3 = "CreatePayloadThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAN_2147920817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAN!MTB"
        threat_id = "2147920817"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d e1}  //weight: 1, accuracy: High
        $x_1_2 = "encryptedShellcode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAT_2147921797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAT!MTB"
        threat_id = "2147921797"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 11 06 8f ?? 00 00 01 25 71 ?? 00 00 01 11 06 0e 04 58 20 ff 00 00 00 5f d2 61 d2 81 ?? 00 00 01 1f 0e 13 12}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAW_2147921808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAW!MTB"
        threat_id = "2147921808"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1a 5d 16 fe 01 13 05 11 05 2c 12 08 07 11 04 91 1f 5b 61 b4 6f ?? 00 00 0a 00 00 2b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BQ_2147922276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BQ!MTB"
        threat_id = "2147922276"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {91 11 04 61 09 11 06 91 61}  //weight: 4, accuracy: High
        $x_2_2 = {07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 08 18 58 0c 08 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AMD_2147922512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AMD!MTB"
        threat_id = "2147922512"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1d 5d 16 fe 01 [0-16] 61 b4 9c 00 00 [0-5] 17 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARAX_2147923129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARAX!MTB"
        threat_id = "2147923129"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 06 08 03 08 91 04 08 04 8e 69 5d 91 61 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 0a 9c 00 08 17 58 0c 08 03 8e 69 fe 04 0d 09 2d d5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAZ_2147923514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAZ!MTB"
        threat_id = "2147923514"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "14FE030A11041C932079CD0000590D2BA7062C04160D2BA01B2BFA027B0B00000" ascii //weight: 3
        $x_4_2 = "0000280400002B14FE030A1C0D2BB8062C111104" ascii //weight: 4
        $x_5_3 = "7E220000041F23917E220000041F2491" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDAD_2147923575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDAD!MTB"
        threat_id = "2147923575"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 17 11 17 11 15 28 1e 00 00 0a 6f 1f 00 00 0a 6f 1f 00 00 0a 13 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDAE_2147923614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDAE!MTB"
        threat_id = "2147923614"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 11 0c 95 13 0f 11 0e 11 0f 61 13 10 09 11 0d 11 10 d2 9c 11 05 17 58 13 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDAF_2147925232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDAF!MTB"
        threat_id = "2147925232"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {d0 27 00 00 01 28 29 00 00 0a 11 0a 11 07 17 6f 2a 00 00 0a 28 2b 00 00 0a 28 01 00 00 2b 6f 2d 00 00 0a 26}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDAG_2147925746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDAG!MTB"
        threat_id = "2147925746"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "9cfad5b8-559c-4adf-8d9f-12d587e80427" ascii //weight: 2
        $x_1_2 = "Chrome Installer" ascii //weight: 1
        $x_1_3 = "Google LLC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RDAH_2147926228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RDAH!MTB"
        threat_id = "2147926228"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {a2 25 17 d0 02 00 00 1b 28 17 00 00 0a a2 6f 18 00 00 0a 06 18 8d 0c 00 00 01 25 16 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ARAF_2147926726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ARAF!MTB"
        threat_id = "2147926726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AsyncClient.g.resources" ascii //weight: 2
        $x_2_2 = "Stub.exe" ascii //weight: 2
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_1_5 = "RijndaelManaged" ascii //weight: 1
        $x_1_6 = "StrReverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_AYA_2147926815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.AYA!MTB"
        threat_id = "2147926815"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/c schtasks /create /f /sc onlogon /rl highest /tn" wide //weight: 2
        $x_1_2 = "Select * from AntivirusProduct" wide //weight: 1
        $x_1_3 = "DcRatByqwqdanchun" wide //weight: 1
        $x_1_4 = "RemoteDebuggerPresent" wide //weight: 1
        $x_1_5 = "masterKey can not be null or empty." wide //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_7 = "Paste_bin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PPXH_2147927514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PPXH!MTB"
        threat_id = "2147927514"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {25 16 08 1f 10 63 20 ?? ?? ?? ?? 5f d2 9c 25 17 08 1e 63 20 ?? ?? ?? ?? 5f d2 9c 25 18 08 20 ?? ?? ?? ?? 5f d2 9c}  //weight: 6, accuracy: Low
        $x_5_2 = {25 16 0f 01 28 ?? ?? ?? ?? 9c 25 17 0f 01 28 ?? ?? ?? ?? 9c 25 18 0f 01 28 ?? ?? ?? ?? 9c 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAAC_2147927903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAAC!MTB"
        threat_id = "2147927903"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 09 03 09 91 04 61 9c 09 17 d6 0d 09 08 31 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAAD_2147928221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAAD!MTB"
        threat_id = "2147928221"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {ee 61 8c 70 9c c1 6d 7f 34 85 4b c8 11 84 00 5a 8d 33 c7 5b c4 0e 03 12}  //weight: 4, accuracy: High
        $x_4_2 = {a8 b6 08 f9 ba 5e 03 40 3a a9 89 73 34 12 66 4f c8 6a e5 49 b8 5a 4a 4c}  //weight: 4, accuracy: High
        $x_3_3 = "RC2CryptoServiceProvider" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RVA_2147928886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RVA!MTB"
        threat_id = "2147928886"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 9d a2 29 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 8a 00 00 00 34 00 00 00 d6 00 00 00 fd 00 00 00 d4 00 00 00 22 01 00 00 06 00 00 00 27 00 00 00 01 00 00 00 1e 00 00 00 0c 00 00 00 2b 00 00 00 46 00 00 00 3c 00 00 00 01 00 00 00 01 00 00 00 06 00 00 00 0e 00 00 00 0c 00 00 00 18}  //weight: 1, accuracy: High
        $x_1_2 = "4FEB1358-5011-472C-B1F1-02EF72B2D53A" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_SKHP_2147929159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.SKHP!MTB"
        threat_id = "2147929159"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 07 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PLPH_2147929410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PLPH!MTB"
        threat_id = "2147929410"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 07 1f 20 8d ?? 00 00 01 25 d0 ?? 03 00 04 28 ?? 01 00 0a 6f ?? 01 00 0a 07 1f 10 8d ?? 00 00 01 25 d0 16 03 00 04 28 ?? 01 00 0a 6f ?? 01 00 0a 06 07 6f ?? 01 00 0a 17 73 ?? 00 00 0a 25 02 16 02 8e 69 6f ?? 01 00 0a 6f ?? 01 00 0a 06}  //weight: 10, accuracy: Low
        $x_1_2 = "P88IFbFCKxDwNZIbQx" wide //weight: 1
        $x_1_3 = "rI4RRvfM0p0bS6mTOMsxI7" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_SCHG_2147929466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.SCHG!MTB"
        threat_id = "2147929466"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0d 02 16 09 16 09 8e 69 28 ?? 00 00 0a 06 09 6f ?? 00 00 0a 02 8e 69 09 8e 69 59 8d 1c 00 00 01 13 04 02 09 8e 69 11 04 16 11 04 8e 69 28 ?? 00 00 0a 06 6f ?? 00 00 0a 13 05 11 05 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 06 de 20 11 05 2c 07 11 05 6f ?? 00 00 0a dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PLSH_2147929498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PLSH!MTB"
        threat_id = "2147929498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 0c 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 09 08 1e 28 ?? 00 00 06 06 08 28 ?? 00 00 06 02 06 6f ?? 00 00 0a 28 ?? 00 00 06 13 04 28 ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 dd ?? 00 00 00 07 39 ?? 00 00 00 07}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PLLCH_2147929866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PLLCH!MTB"
        threat_id = "2147929866"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 07 8e 69 8d ?? 00 00 01 0c 7e ?? 00 00 04 13 04 2b 18 08 11 04 07 11 04 91 03 11 04 03 8e 69 5d 91 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 e1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PLLIH_2147930058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PLLIH!MTB"
        threat_id = "2147930058"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 0a 0c 08 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 28 ?? 00 00 0a 09 07 16 07 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 0a}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PLLQH_2147930688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PLLQH!MTB"
        threat_id = "2147930688"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {38 a3 00 00 00 2b 3c 72 ?? 07 00 70 2b 38 2b 3d 2b 42 72 ?? 07 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 1a 2c 1d 08 6f ?? 00 00 0a 0d 28 ?? 00 00 0a 09 07 16 07 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 0a de 1e}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_KAAF_2147930715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.KAAF!MTB"
        threat_id = "2147930715"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {e4 05 20 00 4c 00 20 00 e4 05 e4 05 6f 00 20 00 61 00 20 00 64 00 e4 05 20 00 e4 05}  //weight: 4, accuracy: High
        $x_3_2 = {20 00 20 00 20 00 45 00 20 00 e4 05 6e 00 20 00 20 00 e4 05 20 00 74 00 20 00 20 00 e4 05 20 00 72 00 20 00 20 00 e4 05 20 00 20 00 20 00 79 00 20 00 70 00 e4 05 e4 05 e4 05 20 00 6f 00 20 00 69 00 20 00 6e 00 20 00 e4 05 e4 05 74 00}  //weight: 3, accuracy: High
        $x_3_3 = {20 00 69 00 20 00 e4 05 e4 05 20 00 6e 00 20 00 e4 05 e4 05 20 00 20 00 20 00 76 00 20 00 20 00 20 00 e4 05 e4 05 20 00 20 00 6f 00 20 00 e4 05 e4 05 20 00 6b 00 20 00 e4 05 e4 05 20 00 65 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PLIGH_2147931267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PLIGH!MTB"
        threat_id = "2147931267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {01 25 16 02 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 02 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 02 20 ?? 00 00 00 5f d2 9c 0a 2b 00 06 2a}  //weight: 6, accuracy: Low
        $x_5_2 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0a 2b 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_SVCI_2147932396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.SVCI!MTB"
        threat_id = "2147932396"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 16 06 8e 69 6f ?? 04 00 0a 13 04 1c 2c ed de 37 09 2b de 07 2b dd 6f ?? 04 00 0a 2b d8 09 2b d7 08 2b d6 6f ?? 04 00 0a 2b d1 09 2b d0 6f ?? 04 00 0a 2b cb 1c 2c 09 09 2c 06 09 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_SPY_2147932965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.SPY!MTB"
        threat_id = "2147932965"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 73 09 00 00 0a 0c 08 07 17 73 0a 00 00 0a 0d 09 03 16 03 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 04 de 1e 09 2c 06 09 6f ?? 00 00 0a dc}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_SSPK_2147933665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.SSPK!MTB"
        threat_id = "2147933665"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {63 d1 13 11 11 1e 11 09 91 13 21 11 1e 11 09 11 22 11 21 61 19 11 1c 58 61 11 2f 61 d2 9c}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_PHX_2147934992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.PHX!MTB"
        threat_id = "2147934992"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 11 04 02 11 04 7e ?? 00 00 04 1f 1f 5f 62 6f ?? 00 00 0a 28 ?? 00 00 06 7e ?? 00 00 04 7e ?? 00 00 04 7e ?? 00 00 04 58 7e ?? 00 00 04 58 7e ?? 00 00 04 58 5a 1f 1f 5f 62 02 11 04 7e ?? 00 00 04 1f 1f 5f 62 7e ?? 00 00 04 58 6f ?? 00 00 0a 28 ?? 00 00 06 58 d2 9c 11 04 17 58 13 04 11 04 06 7e ?? 00 00 04 1f 1f 5f 63 32 93}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_SDID_2147935883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.SDID!MTB"
        threat_id = "2147935883"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 0f 00 28 ?? 00 00 0a 1a 5d 0f 00 28 ?? 00 00 0a 9c 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 28 ?? 00 00 06 0b 07 28 ?? 00 00 06 0c 2b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_EAC_2147936231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.EAC!MTB"
        threat_id = "2147936231"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 03 07 91 04 07 91 fe 01 16 fe 01 0c 08 39 02 00 00 00 16 0a 00 07 17 58 0b 07 03 8e 69 fe 04 0d 09 2d dc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_EAC_2147936231_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.EAC!MTB"
        threat_id = "2147936231"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 08 11 04 9a 6f 30 00 00 0a 09 28 60 00 00 0a 13 05 11 05 2c 12 00 06 08 11 04 9a 6f 30 00 00 0a 6f 61 00 00 0a 00 00 00 11 04 17 58 13 04 11 04 08 8e 69 fe 04 13 06 11 06 2d c4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_EAF_2147936804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.EAF!MTB"
        threat_id = "2147936804"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 08 11 04 9a 6f 2f 00 00 0a 09 28 5f 00 00 0a 13 05 11 05 2c 12 00 06 08 11 04 9a 6f 2f 00 00 0a 6f 60 00 00 0a 00 00 00 11 04 17 58 13 04 11 04 08 8e 69 fe 04 13 06 11 06 2d c4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ZHW_2147937124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ZHW!MTB"
        threat_id = "2147937124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 06 07 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 02 28 ?? 00 00 0a 0c 06 6f ?? 00 00 0a 0d 09 08 16 08 8e 69 6f ?? 00 00 0a 13 04}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BGA_2147938080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BGA!MTB"
        threat_id = "2147938080"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 91 0c 06 07 06 02 07 59 17 59 91 9c 06 02 07 59 17 59 08 9c 07 17 58 0b 07 02 18 5b 32 e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BGB_2147938611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BGB!MTB"
        threat_id = "2147938611"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 09 17 59 06 09 91 07 61 09 19 5d 17 58 61 09 1d 5d 17 58 59 20 ff 00 00 00 5f d2 9c 09 17 58 0d 09 06 8e 69 32 d9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ZWY_2147938959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ZWY!MTB"
        threat_id = "2147938959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {08 09 17 59 06 09 91 07 61 1f 0d 59 20 ff 00 00 00 5f d2 9c 09 17 58 0d 09 06 8e 69 32 e2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_WRT_2147939036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.WRT!MTB"
        threat_id = "2147939036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1a 8d 0b 00 00 01 0b 06 07 16 07 8e 69 6f ?? 00 00 0a 26 07 16 28 ?? 00 00 0a 0c 06 16 73 14 00 00 0a 0d 08 8d 0b 00 00 01 13 04 16 13 05 38 13 00 00 00 11 05 09 11 04 11 05 08 11 05 59 6f ?? 00 00 0a 58 13 05 11 05 08 32 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_BGC_2147939509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.BGC!MTB"
        threat_id = "2147939509"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 09 17 59 06 09 91 07 61 1f 0d 59 20 ff 00 00 00 5f d2 9c 09 17 58 0d 09 06 8e 69 32 e2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ZKY_2147940640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ZKY!MTB"
        threat_id = "2147940640"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {58 20 00 01 00 00 5d 94 fe 0e 0e 00 fe 0c 07 00 fe 0c 0c 00 fe 09 00 00 fe 0c 0c 00 91 fe 0c 0e 00 61 28 ?? 00 00 0a 9c fe 0c 0c 00 20 01 00 00 00 58 fe 0e 0c 00 fe 0c 0c 00 fe 09 00 00 8e 69}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ZSW_2147940684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ZSW!MTB"
        threat_id = "2147940684"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {02 11 06 11 08 6f ?? 00 00 0a 13 09 11 04 11 05 8e 69 6f ?? 00 00 0a 13 0b 11 0b 2c 39 00 00 11 05 13 0c 16 13 0d}  //weight: 6, accuracy: Low
        $x_5_2 = {01 25 16 12 09 28 ?? 00 00 0a 9c 25 17 12 09 28 ?? 00 00 0a 9c 25 18 12 09 28 ?? 00 00 0a 9c 13 13 16 13 14 2b 14}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_JK_2147940698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.JK!MTB"
        threat_id = "2147940698"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {06 02 28 0b 00 00 06 28 06 00 00 06 28 1f 00 00 0a 06 28 20 00 00 0a 26 28 1c 00 00 0a 72 27 00 00 70 28 1d 00 00 0a 0b 07 02 28 0c 00 00 06 28 06 00 00 06 28 1f 00 00 0a 07 28 20 00 00 0a 26 02 28 21 00 00 0a 2a}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RPA_2147942884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RPA!MTB"
        threat_id = "2147942884"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "coposProject.forgotpasswordForm.resources" ascii //weight: 1
        $x_1_2 = "coposProject.statisticsForm.resources" ascii //weight: 1
        $x_1_3 = "coposProject.historyForm.resources" ascii //weight: 1
        $x_1_4 = "coposProject.startFormTwo.resources" ascii //weight: 1
        $x_1_5 = "coposProject.startFormThree.resources" ascii //weight: 1
        $x_1_6 = "coposProject.ucInventoryEmployee.resources" ascii //weight: 1
        $x_1_7 = "coposProject.ucSalesEmployee.resources" ascii //weight: 1
        $x_1_8 = "coposProject.ucSalesReceiptEmployee.resources" ascii //weight: 1
        $x_1_9 = "coposProject.ucReceiptPo.resources" ascii //weight: 1
        $x_1_10 = "coposProject.ucInventory.resources" ascii //weight: 1
        $x_100_11 = "coposProject.userControl.purchaseOrderUc.resources" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_RPC_2147943834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.RPC!MTB"
        threat_id = "2147943834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "110"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {73 12 00 00 06 73 ?? 00 00 06 28 ?? 00 00 06 73 ?? 00 00 06 6f ?? 00 00 06 72 ?? 00 00 70 72 ?? 00 00 70 73 ?? 00 00 06 6f ?? 00 00 06 11 ?? 11 00 6f ?? 00 00 0a 11 ?? 6f}  //weight: 100, accuracy: Low
        $x_1_2 = "process_working_set" wide //weight: 1
        $x_1_3 = "Process working set" wide //weight: 1
        $x_1_4 = "process_cpu_seconds_total" wide //weight: 1
        $x_1_5 = "Total user and system CPU time spent in seconds" wide //weight: 1
        $x_1_6 = "process_private_bytes" wide //weight: 1
        $x_1_7 = "process_num_threads" wide //weight: 1
        $x_1_8 = "process_start_time_seconds" wide //weight: 1
        $x_1_9 = "process_virtual_bytes" wide //weight: 1
        $x_1_10 = "Process virtual memory size" wide //weight: 1
        $x_1_11 = "process_processid" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ZXT_2147943916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ZXT!MTB"
        threat_id = "2147943916"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 02 11 04 11 00 11 04 91 11 01 11 04 11 01 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 20 02 00 00 00 38 13 ff ff ff 72 01 00 00 70 13 01 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 f8 fe ff ff 26 20 01 00 00 00 38 ed fe ff ff 38 58 ff ff ff 20 03 00 00 00 38 de fe ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_ZBV_2147944767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.ZBV!MTB"
        threat_id = "2147944767"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0b 07 28 ?? 00 00 0a 04 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 6f ?? 00 00 0a 00 09 18 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 04 11 04 05 16 05 8e 69 6f ?? 00 00 0a 13 05 09}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_GZN_2147945036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.GZN!MTB"
        threat_id = "2147945036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KillSystemSettingsProcess" ascii //weight: 1
        $x_1_2 = "\\NjRat" ascii //weight: 1
        $x_1_3 = "KillSwitch" ascii //weight: 1
        $x_1_4 = "killing SystemSettings" ascii //weight: 1
        $x_1_5 = "Task Kill" ascii //weight: 1
        $x_1_6 = "Process Hacker" ascii //weight: 1
        $x_1_7 = "HijackCleaner64" ascii //weight: 1
        $x_1_8 = "PowerShell" ascii //weight: 1
        $x_1_9 = "Wireshark" ascii //weight: 1
        $x_1_10 = "confuser" ascii //weight: 1
        $x_1_11 = "Procmon" ascii //weight: 1
        $x_1_12 = "Process Explorer" ascii //weight: 1
        $x_1_13 = "Xvirus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_GVA_2147946807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.GVA!MTB"
        threat_id = "2147946807"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 66 06 20 a2 e7 ff ff 58 3b 1c 00 00 00 00 20 56 06 00 00 06 06 19 5a 06 1b 5a 58 5f 61 16 3b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRAT_GVB_2147946838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRAT.GVB!MTB"
        threat_id = "2147946838"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 8e 69 8d 54 00 00 01 0a 02 8e 69 17 59 0b 16 0c 38 0e 00 00 00 06 08 02 07 91 9c 07 17 59 0b 08 17 58 0c 08 06 8e 69 32 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

