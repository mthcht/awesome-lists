rule Backdoor_MSIL_Crysan_AA_2147793589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AA!MTB"
        threat_id = "2147793589"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 03 17 fe 02 16 fe 01 0c 08 2c 04 07 0a 2b 34 03 0d 17 13 04 2b 24 07 28 ?? 00 00 0a 11 04 fe 04 13 05 11 05 2c 0d 72 ?? ?? ?? 70 07 28 ?? 00 00 0a 0b 00 00 11 04 17 d6 13 04 11 04 09 31 d7 07 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_3_2 = "System.Net.Sockets" ascii //weight: 3
        $x_3_3 = "HttpWebRequest" ascii //weight: 3
        $x_3_4 = "FtpWebRequest" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_HR_2147797050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.HR!MTB"
        threat_id = "2147797050"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kjufdas.exe" ascii //weight: 1
        $x_1_2 = {43 6c 69 65 6e 74 5f 00 43 6c 69 65 6e 74 5f 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = "System.IO.Compression" ascii //weight: 1
        $x_1_4 = "GZipStream" ascii //weight: 1
        $x_1_5 = "System.Linq" ascii //weight: 1
        $x_1_6 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_7 = "Rfc2898DeriveBytes" ascii //weight: 1
        $x_1_8 = "RSACryptoServiceProvider" ascii //weight: 1
        $x_1_9 = "CreateEncryptor" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AW_2147799490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AW!MTB"
        threat_id = "2147799490"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {07 1f 10 5d 91 61 07 20 ff 00 00 00 5d d1 61 d1 9d 07 17 58 0b 07}  //weight: 10, accuracy: High
        $x_3_2 = "milesfinder" ascii //weight: 3
        $x_3_3 = "duckchoiceselector" ascii //weight: 3
        $x_3_4 = "burcast5" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_CG_2147819176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.CG!MTB"
        threat_id = "2147819176"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0c 16 13 04 2b 18 08 11 04 07 11 04 07 8e 69 5d 91 06 11 04 91 61 d2 9c 11 04 17 58 13 04 11 04 06 8e 69 fe 04 2d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ABN_2147824761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ABN!MTB"
        threat_id = "2147824761"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 28 10 ?? ?? 0a 72 01 ?? ?? 70 6f 11 ?? ?? 0a 6f 12 ?? ?? 0a 00 06 28 10 ?? ?? 0a 72 01 ?? ?? 70 6f 11 ?? ?? 0a 6f 13 ?? ?? 0a 00 06 06 6f 14 ?? ?? 0a 06 6f 15 ?? ?? 0a 6f 16 ?? ?? 0a 0b 73 17 ?? ?? 0a 0c 08}  //weight: 5, accuracy: Low
        $x_5_2 = {07 17 73 18 ?? ?? 0a 0d 28 19 ?? ?? 0a 6f 1a ?? ?? 0a 72 23 ?? ?? 70 72 33 ?? ?? 70 6f 1b ?? ?? 0a 28 1c ?? ?? 0a 13 04 28 1d ?? ?? 0a 72 35 ?? ?? 70 28 19 ?? ?? 0a 6f 1a ?? ?? 0a 72 23 ?? ?? 70 72 33 ?? ?? 70 6f 1b ?? ?? 0a 28 1e ?? ?? 0a 28 1c ?? ?? 0a 13 05 11 05}  //weight: 5, accuracy: Low
        $x_1_3 = "get_CurrentDomain" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
        $x_1_6 = "ReadAllText" ascii //weight: 1
        $x_1_7 = "get_CurrentDirectory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ABR_2147824762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ABR!MTB"
        threat_id = "2147824762"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 03 00 2b 07 6f 07 ?? ?? 0a 2b f6 00 de 11 08 2b 08 08 6f 08 ?? ?? 0a 2b 04 2c 03 2b f4 00 dc 40 00 00 02 73 03 ?? ?? 0a 0a 00 73 04 ?? ?? 0a 0b 00 06 16 73 05 ?? ?? 0a 73 06 ?? ?? 0a 0c 00 08 07}  //weight: 5, accuracy: Low
        $x_1_2 = "PasswordRestriction" ascii //weight: 1
        $x_1_3 = "VirusInfected" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
        $x_1_6 = "AesCryptoServiceProvider" ascii //weight: 1
        $x_1_7 = "CreateDelegate" ascii //weight: 1
        $x_1_8 = "Debugger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ABX_2147827398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ABX!MTB"
        threat_id = "2147827398"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 09 11 04 28 10 ?? ?? 0a 6f 11 ?? ?? 0a 13 07 72 01 ?? ?? 70 13 08 28 12 ?? ?? 0a 11 07 6f 13 ?? ?? 0a 13 09 28 14 ?? ?? 0a 13 0a 1a 8d 01 ?? ?? 01 13 0e 11 0e 16 11 0a a2 11 0e}  //weight: 1, accuracy: Low
        $x_1_2 = {13 0b 11 09 72 b6 ?? ?? 70 6f 16 ?? ?? 0a 11 05 20 00 ?? ?? 00 14 14 11 0b 74 01 ?? ?? 1b 6f 17 ?? ?? 0a 41 00 17 7e 15 ?? ?? 0a a2 11 0e 18 11 08 28 02 ?? ?? 06 a2 11 0e 19 17 8c 19 ?? ?? 01 a2 11 0e}  //weight: 1, accuracy: Low
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "get_ExecutablePath" ascii //weight: 1
        $x_1_5 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ABU_2147827746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ABU!MTB"
        threat_id = "2147827746"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 11 08 95 06 11 08 1f 0f 5f 95 61 13 09 06 11 08 1f 0f 5f 06 11 08 1f 0f 5f 95 11 09 61 20 19 ?? ?? 3d 58 9e 09 11 04 11 09 d2 9c 09 11 04}  //weight: 3, accuracy: Low
        $x_3_2 = {08 16 1a 28 2d ?? ?? 0a 08 16 28 2e ?? ?? 0a 13 04 11 04 8d 18 ?? ?? 01 25 17 73 2f ?? ?? 0a 13 05 06 6f 27 ?? ?? 0a 1b 6a 59}  //weight: 3, accuracy: Low
        $x_1_3 = "ReverseDecode" ascii //weight: 1
        $x_1_4 = "DecodeWithMatchByte" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "DecodeDirectBits" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ABL_2147828472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ABL!MTB"
        threat_id = "2147828472"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 17 02 1e 09 0a 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 45 00 00 00 14 00 00 00 0d 00 00 00 30 00 00 00 0b 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = "get_IsAttached" ascii //weight: 1
        $x_1_3 = "IsLogging" ascii //weight: 1
        $x_1_4 = "GetTempPath" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
        $x_1_7 = "cmd.exe /k START" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ABD_2147828599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ABD!MTB"
        threat_id = "2147828599"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 94 02 3c 49 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 28 00 00 00 0c 00 00 00 2b 00 00 00 70 00 00 00 3f 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "MemoryStream" ascii //weight: 1
        $x_1_3 = "DecodeDirectBits" ascii //weight: 1
        $x_1_4 = "get_IsAttached" ascii //weight: 1
        $x_1_5 = "IsLogging" ascii //weight: 1
        $x_1_6 = "ConfuserEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ABH_2147829260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ABH!MTB"
        threat_id = "2147829260"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {57 ff b7 3f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 69 04 00 00 a8 0c 00 00 b7 52 00 00 6c ca 00 00 b5 8e 00 00 3d 03 00 00}  //weight: 4, accuracy: High
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "Debugger" ascii //weight: 1
        $x_1_5 = "get_IsAttached" ascii //weight: 1
        $x_1_6 = "IsLogging" ascii //weight: 1
        $x_1_7 = "GetTempPath" ascii //weight: 1
        $x_1_8 = "Confuser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ABH_2147829260_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ABH!MTB"
        threat_id = "2147829260"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 13 04 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff 11 07 6f ?? ?? ?? 0a 11 04 16 11 04 8e 69 28 ?? ?? ?? 06 13 09}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
        $x_1_4 = "Ksiruniryw" wide //weight: 1
        $x_1_5 = "Vztcnvfnpxptrcdar" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ABH_2147829260_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ABH!MTB"
        threat_id = "2147829260"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 09 6f 19 ?? ?? 0a 7e 13 ?? ?? 04 73 1a ?? ?? 0a 13 06 11 06 02 7e 14 ?? ?? 04 02 8e 69 6f 1b ?? ?? 0a 11 06 6f 1c ?? ?? 0a dd 0f ?? ?? 00 11 06 39 07 ?? ?? 00 11 06 6f 1d ?? ?? 0a dc 08 6f 1e ?? ?? 0a 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "btqbqwwcetacrceatrwb.resources" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ABM_2147830990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ABM!MTB"
        threat_id = "2147830990"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateInstance" ascii //weight: 1
        $x_1_2 = "Rfc2898DeriveBytes" ascii //weight: 1
        $x_1_3 = "FlushFinalBlock" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "Stub.g.resources" ascii //weight: 1
        $x_1_6 = "aR3nbf8dQp2feLmk31.SplashForm.resources" ascii //weight: 1
        $x_1_7 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ABS_2147831436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ABS!MTB"
        threat_id = "2147831436"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 ff b7 3f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 f5 03 00 00 47 0b 00 00 44 4e 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "OleGetClipboard" ascii //weight: 1
        $x_1_3 = "get_IsAttached" ascii //weight: 1
        $x_1_4 = "IsLogging" ascii //weight: 1
        $x_1_5 = "CreateEncryptor" ascii //weight: 1
        $x_1_6 = "FlushFinalBlock" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "ConfuserEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ABG_2147831798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ABG!MTB"
        threat_id = "2147831798"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 00 11 01 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 03 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 20 ?? ?? ?? 00 73 ?? ?? ?? 0a 13 05 38 ?? ?? ?? 00 11 01 11 05 11 01 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 38 ?? ?? ?? 00 11 00 6f ?? ?? ?? 0a 13 04}  //weight: 5, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "Rfc2898DeriveBytes" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "Zowmhyqwcdnzvkegp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ABE_2147832231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ABE!MTB"
        threat_id = "2147832231"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {13 04 11 04 09 17 73 ?? ?? ?? 0a 13 05 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 2c 5b 06 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 58 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 06 11 05 11 06 16 11 06 8e 69 6f ?? ?? ?? 0a 11 05 6f ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 14 16}  //weight: 3, accuracy: Low
        $x_1_2 = "AfzdIHOfGi7323Sf" wide //weight: 1
        $x_1_3 = "2141WKnjxerCybNLBusdu2vcq4N8InJd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ABI_2147832738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ABI!MTB"
        threat_id = "2147832738"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 95 02 28 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 38 00 00 00 51 00 00 00 4e 00 00 00 b6 00 00 00 04 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "Debugger" ascii //weight: 1
        $x_1_3 = "get_IsAttached" ascii //weight: 1
        $x_1_4 = "IsLogging" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "get_CurrentDomain" ascii //weight: 1
        $x_1_7 = "InvokeMember" ascii //weight: 1
        $x_1_8 = "Lxeomrccwlkmf7.exe" ascii //weight: 1
        $x_1_9 = "$172c2df2-36fe-4384-b440-be04cb68e4cc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ABHC_2147837962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ABHC!MTB"
        threat_id = "2147837962"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 06 0b 16 8d ?? ?? ?? 01 0c 07 7e ?? ?? ?? 04 25 2d 17 26 7e ?? ?? ?? 04 fe ?? ?? ?? ?? 06 73 ?? ?? ?? 0a 25 80 ?? ?? ?? 04 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 0c d0 ?? ?? ?? 01 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0d 09 14 6f ?? ?? ?? 0a 26 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateInstance" wide //weight: 1
        $x_1_3 = "InvokeMember" wide //weight: 1
        $x_1_4 = "CheckRemoteDebuggerPresent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_SP_2147841024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.SP!MTB"
        threat_id = "2147841024"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 13 05 16 2d d7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_GFG_2147842436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.GFG!MTB"
        threat_id = "2147842436"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 24 16 2d f8 09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 13 05 16 2d d7 11 05 17 58 13 04 11 04 07 8e 69 32 d5 16 2d f6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ABPE_2147843711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ABPE!MTB"
        threat_id = "2147843711"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 2
        $x_2_2 = "000000.g.resources" ascii //weight: 2
        $x_1_3 = "FlushFinalBlock" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AAHF_2147851618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AAHF!MTB"
        threat_id = "2147851618"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 4d 00 00 70 28 ?? 00 00 0a 0a 06 28 ?? 00 00 06 0b 07 02 28 ?? 00 00 06 0c 2b 00 08 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "CFdxtfeM8Tm7AGH46xHb+3IjxJvfAKGafg/PnCSjA+4=" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ASDV_2147890418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ASDV!MTB"
        threat_id = "2147890418"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 06 1a 58 4a 03 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? 01 00 06 03 06 1a 58 4a 1c 58 1b 59 03 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54 06 1a 58 4a 6a 03 8e 69 17 59 16 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ASDW_2147891637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ASDW!MTB"
        threat_id = "2147891637"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pUja9CFv5kjyu6dHW3l5wR2aG77fcV9w8Gdoz7UKQfL" wide //weight: 1
        $x_1_2 = "Debugger is detected (Managed)" wide //weight: 1
        $x_1_3 = "xZE341JHFOU6f7U1Y6Ep5jrYBwsC5wcZs1r147oWWdY5r" wide //weight: 1
        $x_1_4 = "jaA4K6s4NY898V2V7537m90Sh6954J09" wide //weight: 1
        $x_1_5 = "C:\\Users\\root0\\Desktop\\Client.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_KAA_2147891722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.KAA!MTB"
        threat_id = "2147891722"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 05 11 06 11 04 11 06 91 09 28 ?? 00 00 0a 59 d2 9c 11 06 17 58 13 06 11 06 11 04 8e 69 3f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_KAB_2147892125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.KAB!MTB"
        threat_id = "2147892125"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 07 09 06 09 1e 5a 1e 6f ?? 00 00 0a 18 28 ?? 00 00 0a 9c 00 09 17 58 0d 09 07 8e 69 17 59 fe 02 16 fe 01 13 04 11 04 2d d6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AAUA_2147893921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AAUA!MTB"
        threat_id = "2147893921"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 03 17 58 13 03 20 0a 00 00 00 38 ?? ff ff ff 73 ?? 00 00 0a 13 0b 20 08 00 00 00 38 ?? ff ff ff 12 07 28 ?? 00 00 0a 13 0a 20 09 00 00 00 38 ?? ff ff ff 11 0b 11 0a 6f ?? 00 00 0a 20 00 00 00 00 7e ?? 09 00 04 7b ?? 09 00 04 39 ?? fe ff ff 26 20 00 00 00 00 38 ?? fe ff ff 11 01 11 03 16 28 ?? 00 00 06 13 07 20 07 00 00 00 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AAUR_2147894643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AAUR!MTB"
        threat_id = "2147894643"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0a 06 72 0d 00 00 70 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 72 c2 00 00 70 73 ?? 00 00 0a 0d 08 09 6f ?? 00 00 0a 13 04 1a 8d ?? 00 00 01 25 16 72 75 01 00 70 a2 25 17 7e ?? 00 00 0a a2 25 18 11 04 a2 25 19 17 8c ?? 00 00 01 a2 13 05 14 13 07 28 ?? 00 00 0a 07 6f ?? 00 00 0a 13 06}  //weight: 4, accuracy: Low
        $x_1_2 = "Anasayfa.sooner" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AAUZ_2147895055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AAUZ!MTB"
        threat_id = "2147895055"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 72 ?? 00 00 70 73 ?? 00 00 0a 13 08 11 07 11 08 6f ?? 00 00 0a 13 09 1a 8d ?? 00 00 01 25 16 72 ?? 01 00 70 a2 25 17 7e ?? 00 00 0a a2 25 18 11 09 a2 25 19 17 8c ?? 00 00 01 a2 13 0a 14 13 0b 07 28 ?? 00 00 0a 13 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_KAC_2147895799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.KAC!MTB"
        threat_id = "2147895799"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7}  //weight: 5, accuracy: High
        $x_5_2 = "https://fs-im-kefu.7moor-fs1.com" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ASGB_2147897160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ASGB!MTB"
        threat_id = "2147897160"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 16 91 1f 1f 61 6a 1e 62 09 1d 91 1f 21 61 6a 1f 20 62 09 19 91 20 ed 00 00 00 61 6a 16 62 09 17 91 1f 11 61 6a 1f 10 62 09 1c 91 20 f1 00 00 00 61 6a 1f 28 62 09 1a 91 20 d2 00 00 00 61 6a 1f 18 62 09 1b 91 20 f9 00 00 00 61 6a 1f 30 62 09 18 91 20 e4 00 00 00 61 6a}  //weight: 1, accuracy: High
        $x_1_2 = {16 fe 01 0a 06 2c 05 28 ?? 00 00 06 20 dc 05 00 00 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AAXG_2147897266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AAXG!MTB"
        threat_id = "2147897266"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 20 0c 00 00 00 97 29 ?? 00 00 11 72 ad 00 00 70 7e ?? 00 00 04 20 0d 00 00 00 97 29 ?? 00 00 11 6f ?? 00 00 0a 0a 06 28 ?? 00 00 06 0b 07 14 fe 03 0c 08 2c 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ASGC_2147897420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ASGC!MTB"
        threat_id = "2147897420"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 c4 09 00 00 28 ?? 00 00 0a 00 28 ?? 02 00 06 16 fe 01 0a 06 39 07 00 00 00 16 28}  //weight: 1, accuracy: Low
        $x_1_2 = {16 fe 01 0c 08 39 ?? 00 00 00 28 ?? 01 00 06 00 20 dc 05 00 00 28 ?? 00 00 0a 00 00 17 0d 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AAXM_2147897511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AAXM!MTB"
        threat_id = "2147897511"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 07 08 1f 20 6f ?? 00 00 0a 6f ?? 00 00 0a 07 08 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 73 ?? 00 00 0a 0d 09 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 04 11 04 02 16 02 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a de 0b 26 09 6f ?? 00 00 0a 13 05 de 2f}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "yy6zDjAUmbB09pKvo5Hhug==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AAXT_2147897622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AAXT!MTB"
        threat_id = "2147897622"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 0c 2b 1e 7e ?? 00 00 04 06 08 16 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 08 17 d6 0c 08 07 31 de 7e ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 06 de 25}  //weight: 4, accuracy: Low
        $x_1_2 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_KAD_2147898339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.KAD!MTB"
        threat_id = "2147898339"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {17 64 61 fe 0e 2f 00 fe 0c 2f 00 fe 0c 27 00 58 fe 0e 2f 00 fe 0c 17 00 1e 62 fe 0c 13 00 58 fe 0c 17 00 61 fe 0c 2f 00 58 fe 0e 2f 00 fe 0c 2f 00 76 6c 6d 58 13 2e}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AAZH_2147898771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AAZH!MTB"
        threat_id = "2147898771"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 09 06 07 09 59 17 59 91 9c 06 07 09 59 17 59 11 04 9c 09 18 2c d9 17 58 16 2d 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ASAA_2147900663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ASAA!MTB"
        threat_id = "2147900663"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 0c 07 08 16 7e ?? 00 00 04 6f ?? 00 00 0a 26 08 16 28 ?? 00 00 0a 26 07 16 73 ?? 00 00 0a 0d 09 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 13 04 11 04 16 11 04 8e 69 28 ?? 00 00 0a 11 04 13 05 de 1e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AUAA_2147900680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AUAA!MTB"
        threat_id = "2147900680"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 0c 00 11 0c 11 06 17 73 ?? 00 00 0a 13 0d 11 0d 02 16 02 8e 69 6f ?? 00 00 0a 00 11 0d 6f ?? 00 00 0a 00 de 0e 00 11 0d 2c 08 11 0d 6f ?? 00 00 0a 00 dc 11 0c 6f ?? 00 00 0a 0a de 21}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_BWAA_2147901280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.BWAA!MTB"
        threat_id = "2147901280"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 11 04 28 ?? 00 00 0a 09 6f ?? 00 00 0a 6f ?? 00 00 0a 00 11 04 28 ?? 00 00 0a 09 6f ?? 00 00 0a 6f ?? 00 00 0a 00 11 04 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 11 06 11 05 17}  //weight: 2, accuracy: Low
        $x_2_2 = {13 09 11 07 11 09 16 11 09 8e 69 6f ?? 00 00 0a 00 11 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_MA_2147901653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.MA!MTB"
        threat_id = "2147901653"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Spoofer.exe" wide //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-96] 2f 00 53 00 70 00 6f 00 6f 00 66 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "DownloadFile" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_SPPS_2147901840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.SPPS!MTB"
        threat_id = "2147901840"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {26 07 16 73 ?? 00 00 0a 0d 09 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 13 04 11 04 16 11 04 8e 69 28 ?? 00 00 0a 11 04 13 05 de 1e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_DAAA_2147902089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.DAAA!MTB"
        threat_id = "2147902089"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 00 01 13 06 11 06 16 1f 0a 9d 11 06 6f ?? 00 00 0a 0b 27 00 73 ?? 00 00 0a 0a 06 72 ?? 00 00 70 6f ?? 00 00 0a 17 8d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_FVAA_2147903576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.FVAA!MTB"
        threat_id = "2147903576"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {01 0b 16 0c 17 0d 2b 14 08 09 19 2c 0d 16 2d 0e 58 16 2d 09 1a 2c b4 0c 09 17 58 0d 09 02 31 e8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_GLAA_2147904125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.GLAA!MTB"
        threat_id = "2147904125"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 04 2b 21 02 11 04 9a 28 ?? 00 00 0a 20 ?? 00 00 00 da 13 05 08 11 05 b4 6f ?? 00 00 0a 00 11 04 17 d6 13 04 11 04 09 31 da}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_HIAA_2147904854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.HIAA!MTB"
        threat_id = "2147904854"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 07 6f ?? 00 00 0a 16 73 ?? 00 00 0a 13 07 06 6f ?? 00 00 0a 1f 10 6a 59 17 6a 58 d4 8d ?? 00 00 01 13 08 11 07 11 08 16 11 08 8e 69 6f ?? 00 00 0a 8d ?? 00 00 01 13 09 11 08 16 11 09 16 11 09 8e 69 28 ?? 00 00 0a 11 09 13 05 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_HMAA_2147904953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.HMAA!MTB"
        threat_id = "2147904953"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0d 09 28 ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 09 28 ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 09 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 11 05 11 04 17 73 ?? 00 00 0a 13 06}  //weight: 3, accuracy: Low
        $x_2_2 = {13 07 11 06 11 07 16 11 07 8e 69 6f ?? 00 00 0a 11 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_HOAA_2147904971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.HOAA!MTB"
        threat_id = "2147904971"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0c 08 28 ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 08 28 ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05}  //weight: 3, accuracy: Low
        $x_2_2 = {13 06 11 05 11 06 16 11 06 8e 69 6f ?? 00 00 0a 11 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_IMAA_2147905682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.IMAA!MTB"
        threat_id = "2147905682"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 01 11 0c 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 13 0d 20 01 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 0f 00 00 00 26}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_KVAA_2147907928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.KVAA!MTB"
        threat_id = "2147907928"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 18 5d 3a 09 00 00 00 06 02 58 0a 38 04 00 00 00 06 02 59 0a 07 17 58 0b 07 03 32 e3}  //weight: 2, accuracy: High
        $x_2_2 = {04 1f 0a 3b 0d 00 00 00 04 1f 14 3b 0b 00 00 00 38 0c 00 00 00 02 03 5a 04 5b 2a 02 03 58 04 5a 2a 02 03 59 04 5a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_LCAA_2147908238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.LCAA!MTB"
        threat_id = "2147908238"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 0a 20 0f 84 36 e2 28 ?? 1a 00 06 28 ?? 03 00 0a 20 2e 84 36 e2 28 ?? 1a 00 06 28 ?? 03 00 0a 6f ?? 05 00 0a 13 18}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_NGAA_2147911035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.NGAA!MTB"
        threat_id = "2147911035"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 03 11 00 11 03 91 11 02 11 03 11 02 6f ?? 00 00 0a 5d 28 ?? 00 00 06 61 d2 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_OFAA_2147912045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.OFAA!MTB"
        threat_id = "2147912045"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0b 07 72 01 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 72 5b 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 17 73 ?? 00 00 0a 13 04}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_PWAA_2147914060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.PWAA!MTB"
        threat_id = "2147914060"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 14 0b 28 ?? 00 00 06 0b 06 07 6f ?? 00 00 0a 28 ?? 00 00 0a 06 16 6f ?? 00 00 0a 6f ?? 00 00 0a 0c}  //weight: 1, accuracy: Low
        $x_2_2 = {09 08 11 04 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 18 58 13 04 11 04 08 6f ?? 00 00 0a 32 da 06 09 6f ?? 00 00 0a 6f ?? 00 00 0a 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_SK_2147914282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.SK!MTB"
        threat_id = "2147914282"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "5ypkdhesfyhbekwvr2ltfqbwwjmphmya" ascii //weight: 2
        $x_1_2 = "Client.exe" ascii //weight: 1
        $x_1_3 = "Stub.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Crysan_SL_2147914283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.SL!MTB"
        threat_id = "2147914283"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 1f 09 5d 16 fe 01 13 05 11 05 2c 0d 06 11 04 06 11 04 91 1f 5e 61 b4 9c 00 00 11 04 17 d6 13 04 11 04 09 31 d9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_SL_2147914283_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.SL!MTB"
        threat_id = "2147914283"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 e4 03 00 00 fe 1c 29 00 00 01 58 28 14 00 00 0a 06 20 fd ff ff ff fe 1c 29 00 00 01 58 58 0a 06 7e 11 00 00 04 28 15 00 00 0a 32 d3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ARA_2147914333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ARA!MTB"
        threat_id = "2147914333"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%RootKit%" wide //weight: 2
        $x_3_2 = "$4a2f8fb6-1077-469a-9246-736e6afe8da1" ascii //weight: 3
        $x_3_3 = "Client.exe" wide //weight: 3
        $x_1_4 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Crysan_RLAA_2147915991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.RLAA!MTB"
        threat_id = "2147915991"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 02 08 20 0f 02 00 00 58 20 0e 02 00 00 59 18 59 18 58 02 8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_SAAA_2147916438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.SAAA!MTB"
        threat_id = "2147916438"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 13 04 73 ?? 00 00 0a 0a 06 11 04 17 73 ?? 03 00 0a 0c 28 ?? ?? 00 06 0d 08 09 28 ?? 00 00 2b 16 09 28 ?? 00 00 2b 8e 69 6f ?? 00 00 0a 06 6f ?? 00 00 0a 13 05 de 15}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_TRAA_2147918295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.TRAA!MTB"
        threat_id = "2147918295"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0b 2b 1d 00 02 7b ?? 00 00 04 07 02 7b ?? 00 00 04 07 91 20 ?? ?? 00 00 59 d2 9c 00 07 17 58 0b 07 02 7b ?? 00 00 04 8e 69 fe 04 0c 08 2d d4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_VUAA_2147920523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.VUAA!MTB"
        threat_id = "2147920523"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 72 15 00 00 70 28 ?? 00 00 0a 72 47 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 10 00 dd 1a}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_XYAA_2147922124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.XYAA!MTB"
        threat_id = "2147922124"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 09 91 08 09 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 09 17 58 0d 09 06 8e 69 32 de 07 2a 02 2b b7 28 ?? ?? 00 06 2b b2 0a 2b b6 06 2b b5 0b 2b bb 0c 2b bf 0d 2b c1 07 2b c2 09 2b c1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_YLAA_2147922507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.YLAA!MTB"
        threat_id = "2147922507"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {09 12 04 28 ?? 00 00 0a 07 06 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a de 0b 11 04 2c 06 09 28 ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_2_2 = {08 18 25 2c 0f 58 1b 2c 05 0c 16 2d b7 08 06 6f ?? 00 00 0a 16 2d eb 32 ad 07 6f ?? 00 00 0a 2a 28 ?? 00 00 0a 38 ?? ff ff ff 02 38 ?? ff ff ff 6f ?? 00 00 0a 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ADGA_2147928259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ADGA!MTB"
        threat_id = "2147928259"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {26 2b 46 72 ?? ?? 00 70 2b 42 2b 47 2b 4c 72 ?? ?? 00 70 2b 48 2b 4d 1a 2c 0c 2b 52 6f ?? ?? 00 0a 0b 14 0c}  //weight: 3, accuracy: Low
        $x_2_2 = {07 08 16 08 8e 69 6f ?? ?? 00 0a 0d 1c 2c c5 de 35 06 2b b7 28 ?? ?? 00 0a 2b b7 6f ?? ?? 00 0a 2b b2 06 2b b1 28 ?? ?? 00 0a 2b b1}  //weight: 2, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AZGA_2147928796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AZGA!MTB"
        threat_id = "2147928796"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 04 11 04 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 0a dd}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AFIA_2147929931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AFIA!MTB"
        threat_id = "2147929931"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 00 07 18 6f ?? 00 00 0a 00 00 07 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 00 02 08 28 ?? 00 00 06 0a de 30 00 de 14 08 14 fe 01 16 fe 01 0d 09 2c 07}  //weight: 3, accuracy: Low
        $x_2_2 = {08 02 16 02 8e b7 6f ?? 00 00 0a 00 08 6f ?? 00 00 0a 00 00 de 14 08 14 fe 01 16 fe 01 0d 09}  //weight: 2, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_SM_2147930544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.SM!MTB"
        threat_id = "2147930544"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 11 04 09 28 30 00 00 06 00 11 04 17 58 13 04 00 11 04 07 6f 92 00 00 0a 2f 0b 08 6f 93 00 00 0a 09 fe 04 2b 01 16 13 08 11 08 2d d1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AQIA_2147930699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AQIA!MTB"
        threat_id = "2147930699"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 73 4f 00 00 0a 0d 09 07 6f ?? 00 00 0a 09 08 6f ?? 00 00 0a 09 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 13 04 dd ?? 00 00 00 09 39 ?? 00 00 00 09 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ASIA_2147930728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ASIA!MTB"
        threat_id = "2147930728"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 2d 29 2b 45 72 ?? ?? 00 70 2b 41 2b 46 2b 4b 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 16 2d de 16 2d 23 08 6f ?? 00 00 0a 0d 16 2d 19 16 2d ce 28 ?? 00 00 0a 09 07 16 07 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 0a de 1e}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AVIA_2147930832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AVIA!MTB"
        threat_id = "2147930832"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 73 46 00 00 0a 0d 09 07 6f ?? 00 00 0a 09 08 6f ?? 00 00 0a 09 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 13 04 dd}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AOLA_2147933663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AOLA!MTB"
        threat_id = "2147933663"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0a 06 20 00 01 00 00 6f ?? 00 00 0a 06 20 f3 79 12 4b 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 20 c0 79 12 4b 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 0b 20 10 a8 04 00 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 73 ?? 00 00 0a 0c 08 11 04 16 73 ?? 00 00 0a 0d 09 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 06 13 05 de}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_APLA_2147933664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.APLA!MTB"
        threat_id = "2147933664"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 08 02 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 13 05 11 05 2d df}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AQNA_2147935715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AQNA!MTB"
        threat_id = "2147935715"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0a 06 20 00 01 00 00 6f ?? 00 00 0a 06 20 ?? 69 28 e7 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 20 ?? 69 28 e7 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 0b 20 30 b1 04 00 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 73 ?? 00 00 0a 0c 08 11 04 16 73 ?? 00 00 0a 0d 09 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 06 13 05 de 1f}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AWNA_2147935874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AWNA!MTB"
        threat_id = "2147935874"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0a 06 20 00 01 00 00 6f ?? 00 00 0a 06 20 ?? 04 70 23 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 20 ?? 04 70 23 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 0b 20 20 ab 04 00 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 73 ?? 00 00 0a 0c 08 11 04 16 73 ?? 00 00 0a 0d 09 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 06 13 05 de 1f}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AHPA_2147937029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AHPA!MTB"
        threat_id = "2147937029"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0b 2b 28 72 ?? ?? 00 70 2b 24 2b 29 2b 2e 72 ?? ?? 00 70 2b 2a 2b 2f 2b 34 2b 35 06 16 06 8e 69 6f ?? ?? 00 0a 0c 1e 2c e3 de 44 07 2b d5 28 ?? ?? 00 0a 2b d5 6f ?? ?? 00 0a 2b d0 07 2b cf 28 ?? ?? 00 0a 2b cf 6f ?? ?? 00 0a 2b ca 07 2b c9 6f ?? ?? 00 0a 2b c4}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AYJA_2147937051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AYJA!MTB"
        threat_id = "2147937051"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 08 06 6f ?? 00 00 0a 08 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 09 03 16 03 8e 69 6f ?? 00 00 0a 13 04 dd ?? 00 00 00 09 39 ?? 00 00 00 09 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ASPA_2147937383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ASPA!MTB"
        threat_id = "2147937383"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 07 91 0c 08 18 28 ?? 00 00 06 0c 08 03 59 07 59 20 ff 00 00 00 5f d2 0c 08 66 d2 0c 06 07 08 9c 07 17 58 0b}  //weight: 5, accuracy: Low
        $x_2_2 = {0a 25 06 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 0b dd}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ADRA_2147939253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ADRA!MTB"
        threat_id = "2147939253"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 0b 06 07 16 1a 6f ?? 00 00 0a 26 07 16 28 ?? 00 00 0a 0c 06 16 73 ?? 00 00 0a 0d 08 8d ?? 00 00 01 13 04 16 13 05 38 1e 00 00 00 09 11 04 11 05 08 11 05 59 6f ?? 00 00 0a 13 06 11 06 39 0c 00 00 00 11 05 11 06 58 13 05 11 05 08 32 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_NIT_2147941025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.NIT!MTB"
        threat_id = "2147941025"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 7b 01 00 00 04 6f ?? 00 00 0a 0a 06 8e 69 18 3c 01 00 00 00 2a 06 16 9a 75 03 00 00 01 0b 07 14 28 ?? 00 00 0a 39 01 00 00 00 2a 07 6f ?? 00 00 0a 7e 03 00 00 04 25 3a 17 00 00 00 26 7e 02 00 00 04 fe 06 0b 00 00 06 73 06 00 00 0a 25 80 03 00 00 04 28 ?? 00 00 2b 0c 08 14 28 ?? 00 00 0a 39 0c 00 00 00 02 7b 01 00 00 04 08 6f ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ARWA_2147943883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ARWA!MTB"
        threat_id = "2147943883"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 06 28 ?? 00 00 0a 0a 06 20 00 01 00 00 6f ?? 00 00 0a 06 11 05 6f ?? 00 00 0a 06 11 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0b 02 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 73 ?? 00 00 0a 0c 11 04 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 07 de 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AYWA_2147945640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AYWA!MTB"
        threat_id = "2147945640"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 02 11 03 11 04 11 03 91 11 01 11 03 11 01 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 20}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_SN_2147946433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.SN!MTB"
        threat_id = "2147946433"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 6f 0a 00 00 0a 0d 09 02 16 02 8e 69 6f 0b 00 00 0a 13 04 dd 1a 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_SO_2147946850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.SO!MTB"
        threat_id = "2147946850"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 28 35 00 00 06 0a dd 09 00 00 00 26 dd 00 00 00 00 06 2c eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AZCB_2147949881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AZCB!MTB"
        threat_id = "2147949881"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0a 06 20 00 01 00 00 6f ?? 00 00 0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 03 6f ?? 00 00 0a 06 04 6f ?? 00 00 0a 73 ?? 00 00 0a 0b 07 06 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 6f ?? 00 00 0a 0d de 1e}  //weight: 10, accuracy: Low
        $x_2_2 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7}  //weight: 2, accuracy: High
        $x_10_3 = {0a 13 06 11 06 11 05 6f ?? 00 00 0a 16 73 ?? 00 00 0a 13 07 73 ?? 00 00 0a 13 08 00 11 07 11 08 6f ?? 00 00 0a 00 11 08 6f ?? 00 00 0a 13 04 00 de 14}  //weight: 10, accuracy: Low
        $x_2_4 = {16 0d 2b 1d 06 09 8f ?? 00 00 01 25 71 ?? 00 00 01 20 aa 00 00 00 61 d2 81 ?? 00 00 01 09 17 58 0d 09 06 8e 69 fe 04 13 0b 11 0b 2d d7}  //weight: 2, accuracy: Low
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Crysan_AILB_2147957792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AILB!MTB"
        threat_id = "2147957792"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 07 20 00 01 00 00 6f ?? 00 00 0a 07 06 6f ?? 00 00 0a 07 18 6f ?? 00 00 0a 20 f4 01 00 00 28 ?? 00 00 0a 07 6f ?? 00 00 0a 7e ?? 00 00 04 16 7e ?? 00 00 04 8e 69 6f ?? 00 00 0a 0c 08 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AMLB_2147957867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AMLB!MTB"
        threat_id = "2147957867"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 08 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 08 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0b de 0a 08 2c 06 08 6f ?? 00 00 0a dc 28 ?? 00 00 0a 07 6f ?? 00 00 0a 0d 09 14 28 ?? 00 00 0a 2d 63 09}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AOLB_2147957881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AOLB!MTB"
        threat_id = "2147957881"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 08 09 8e 69 08 8e 69 28 ?? 00 00 0a 28 ?? 00 00 0a 06 07 6f ?? 00 00 0a 06 08 6f ?? 00 00 0a 06 6f ?? 00 00 0a 13 04 11 04 02 16 02 8e 69 6f ?? 00 00 0a 13 05 11 05 8e 69 04 59 8d ?? 00 00 01 13 06 11 05 04 11 06 16 11 06 8e 69 28 ?? 00 00 0a 11 06 13 07 dd 0d}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_ACNB_2147959384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.ACNB!MTB"
        threat_id = "2147959384"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {fe 0e 09 00 fe 0c 09 00 20 00 00 00 00 fe 0c 04 00 a2 fe 0c 09 00 20 01 00 00 00 fe 0c 05 00 fe 0c 02 00 20 01 00 00 00 28 ?? 00 00 0a a2 fe 0c 09 00 20 02 00 00 00 fe 0c 06 00 fe 0c 02 00 20 01 00 00 00 28 ?? 00 00 0a a2 fe 0c 09 00 20 03 00 00 00 fe 0c 07 00 fe 0c 02 00 20 01 00 00 00 28 ?? 00 00 0a a2 fe 0c 09 00 20 04 00 00 00 fe 0c 08 00 fe 0c 02 00 20 01 00 00 00 28 ?? 00 00 0a a2 fe 0c 09 00 28 ?? 00 00 0a fe 0e 04 00 fe 0c 02 00 20 01 00 00 00 d6 fe 0e 02 00 fe 0c 02 00 fe 0c 03 00 3e}  //weight: 4, accuracy: Low
        $x_2_2 = {11 09 11 0e 8f 19 00 00 01 25 71 19 00 00 01 11 0c 11 0e 91 61 d2 81 19 00 00 01 11 0e 17 58 13 0e 11 0e 11 08 32 d9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysan_AGNB_2147959503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysan.AGNB!MTB"
        threat_id = "2147959503"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 09 11 0e 8f 16 00 00 01 25 71 16 00 00 01 11 0c 11 0e 91 61 d2 81 16 00 00 01 11 0e 17 58 13 0e 11 0e 11 08 32 d9}  //weight: 2, accuracy: High
        $x_4_2 = {fe 0e 09 00 fe 0c 09 00 20 00 00 00 00 fe 0c 04 00 a2 fe 0c 09 00 20 01 00 00 00 fe 0c 05 00 fe 0c 02 00 20 01 00 00 00 28 ?? 00 00 0a a2 fe 0c 09 00 20 02 00 00 00 fe 0c 06 00 fe 0c 02 00 20 01 00 00 00 28 ?? 00 00 0a a2 fe 0c 09 00 20 03 00 00 00 fe 0c 07 00 fe 0c 02 00 20 01 00 00 00 28 ?? 00 00 0a a2}  //weight: 4, accuracy: Low
        $x_4_3 = {fe 0e 14 00 fe 0c 14 00 20 00 00 00 00 fe 0c 04 00 a2 fe 0c 14 00 20 01 00 00 00 fe 0c 05 00 fe 0c 02 00 20 01 00 00 00 28 ?? 00 00 0a a2 fe 0c 14 00 20 02 00 00 00 fe 0c 0c 00 fe 0c 02 00 20 01 00 00 00 28 ?? 00 00 0a a2 fe 0c 14 00 20 03 00 00 00 fe 0c 0d 00 fe 0c 02 00 20 01 00 00 00 28 ?? 00 00 0a a2}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

