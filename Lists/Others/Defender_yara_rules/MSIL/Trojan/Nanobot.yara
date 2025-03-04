rule Trojan_MSIL_NanoBot_D_2147730018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.D!MTB"
        threat_id = "2147730018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SbieDll.dll" wide //weight: 1
        $x_1_2 = "SANDBOX" wide //weight: 1
        $x_1_3 = "MALWARE" wide //weight: 1
        $x_1_4 = "VIRUS" wide //weight: 1
        $x_1_5 = "VMWARE\\VMWARE TOOLS\\" wide //weight: 1
        $x_1_6 = "VM Additions S3 Trio32/64" wide //weight: 1
        $x_1_7 = "VirtualBox Graphics Adapter" wide //weight: 1
        $x_1_8 = "VMware SVGA II" wide //weight: 1
        $x_1_9 = "MSBuild.exe" wide //weight: 1
        $x_1_10 = "RegAsm.exe" wide //weight: 1
        $x_1_11 = "RegSvcs.exe" wide //weight: 1
        $x_1_12 = "eventvwr.exe" wide //weight: 1
        $x_1_13 = "/Create /TN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

rule Trojan_MSIL_NanoBot_DH_2147744161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.DH!MTB"
        threat_id = "2147744161"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 20 64 06 83 67 02 5a 0a 06 1f 0b 63 0b 02 06 1f 1f 5f 63 0c 28 ?? ?? ?? ?? 00 07 08 58 0d 09 13 04 2b 00 11 04 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoBot_MR_2147775825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.MR!MTB"
        threat_id = "2147775825"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Postie_Notes.Resources.resources" ascii //weight: 1
        $x_1_2 = "get_PostieNote" ascii //weight: 1
        $x_1_3 = "get_ListIDPegawai" ascii //weight: 1
        $x_1_4 = "_NowBtn" ascii //weight: 1
        $x_1_5 = "form_refIdObat_Load" ascii //weight: 1
        $x_1_6 = "Bitmap" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoBot_DA_2147780436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.DA!MTB"
        threat_id = "2147780436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 02 7b 05 00 00 04 02 7b 04 00 00 04 8c 18 00 00 01 28 ?? ?? ?? 0a ?? ?? 04 26 06 2b 03 0a 2b fa 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 03 26 2b 1b 0a 2b fb 06 ?? 2d 0a 26 06 17 58 ?? ?? 0a 26 2b 0a 28 ?? ?? ?? 0a 2b f0 0a 2b 00 06 1b fe 04 0b 07 2d e0 2a}  //weight: 1, accuracy: Low
        $x_1_3 = "{0} with speed{1} km/h" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoBot_DB_2147780439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.DB!MTB"
        threat_id = "2147780439"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 2b 1a 7b 04 00 00 04 2b 16 7b 03 00 00 04 8c 24 00 00 01 2b 0d 2b 12 2b 00 2b 11 2a}  //weight: 1, accuracy: High
        $x_1_2 = {1b fe 04 1c 2d 1c 26 2b 1c 2d dd 2a 0a 2b d4 06 2b dc 28 ?? ?? ?? 0a 2b d7 06 2b da 0a 2b de 06 2b de 0b 2b e2 07 2b e1}  //weight: 1, accuracy: Low
        $x_1_3 = "{0} with speed{1} km/h" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoBot_MFP_2147783941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.MFP!MTB"
        threat_id = "2147783941"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$e5d657a2-7294-4ee2-aed5-c830404b6863" ascii //weight: 1
        $x_1_2 = {57 bd b6 29 09 1f 00 00 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "FromBase64CharArray" ascii //weight: 1
        $x_1_4 = "XOR_Decrypt" ascii //weight: 1
        $x_1_5 = "SuspendLayout" ascii //weight: 1
        $x_1_6 = "Microsoft.Win32" ascii //weight: 1
        $x_1_7 = "GetTempFileName" ascii //weight: 1
        $x_1_8 = "get_ExecutablePath" ascii //weight: 1
        $x_1_9 = "RSACryptoServiceProvider" ascii //weight: 1
        $x_1_10 = "BitConverter" ascii //weight: 1
        $x_1_11 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_12 = "AesCryptoServiceProvider" ascii //weight: 1
        $x_1_13 = "RijndaelManaged" ascii //weight: 1
        $x_1_14 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_15 = "HashAlgorithm" ascii //weight: 1
        $x_1_16 = "CryptoStream" ascii //weight: 1
        $x_1_17 = "BinaryReader" ascii //weight: 1
        $x_1_18 = "MemoryStream" ascii //weight: 1
        $x_1_19 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoBot_S_2147787624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.S!MTB"
        threat_id = "2147787624"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$5cdc1c76-899c-469e-97af-a8c60f861d5e" ascii //weight: 1
        $x_1_2 = "lyMC6=3_" ascii //weight: 1
        $x_1_3 = "CY'0!Lk" ascii //weight: 1
        $x_1_4 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_5 = {57 15 02 08 09 03 00 00 00 fa 01 33 00 16 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoBot_QA_2147796260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.QA!MTB"
        threat_id = "2147796260"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {fa 25 33 00 16 00 00 01 00 00 00 27 00 00 00 17 00 00 00 01 00 00 00 0b 00 00 00 02 00 00 00 14 00 00 00 27 00 00 00 05 00 00 00 03 00 00 00 01 00 00 00 03}  //weight: 10, accuracy: High
        $x_3_2 = "HttpWebResponse" ascii //weight: 3
        $x_3_3 = "HttpWebRequest" ascii //weight: 3
        $x_3_4 = "System.Deployment.Internal.Isolation" ascii //weight: 3
        $x_3_5 = "StoreOperationSetDeploymentMetadata" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoBot_KA_2147806333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.KA!MTB"
        threat_id = "2147806333"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 08 11 04 02 11 04 91 07 61 06 09 91 61 d2 9c 09 03 6f ?? 00 00 0a 17 59 fe 01 13 05 11 05 2c 04 16 0d 2b 04 09 17 58 0d 00 11 04 17 58 13 04 11 04 02 8e 69 fe 04 13 06 11 06 2d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoBot_ABS_2147829925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.ABS!MTB"
        threat_id = "2147829925"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 1d a2 09 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 63 00 00 00 15 00 00 00 49 00 00 00 80 00 00 00 5a 00 00 00 d6 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "Dowd.TreeView.resources" ascii //weight: 1
        $x_1_3 = "GetMethod" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "GetObject" ascii //weight: 1
        $x_1_6 = "$B1624E43-F6A8-46A5-9248-8218CCE1C403" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoBot_MB_2147833619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.MB!MTB"
        threat_id = "2147833619"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "b1683022-08a1-41c2-ae63-d6678662c1ba" ascii //weight: 10
        $x_1_2 = "DisableOrder" ascii //weight: 1
        $x_1_3 = "Dhauhvr.Properties" ascii //weight: 1
        $x_1_4 = "InvokeOrder" ascii //weight: 1
        $x_1_5 = "Milyyre" ascii //weight: 1
        $x_10_6 = "://52.59.30.24/sit/loader/uploads" wide //weight: 10
        $x_1_7 = "/xC timexout /nobrxeak /t 19" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoBot_MBAV_2147838984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.MBAV!MTB"
        threat_id = "2147838984"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TVqQ><><M><><><><E><><><><//8><><Lg><><><><>" wide //weight: 1
        $x_1_2 = "0Q2hhbmdlZD5iX181Xz><><PHJpY2hUZXh" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoBot_BAY_2147840123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.BAY!MTB"
        threat_id = "2147840123"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {26 11 0a 73 ?? 00 00 0a 73 ?? 00 00 0a 08 28 ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 16 73 ?? 00 00 0a 16 73 ?? 00 00 0a 13 0e 20 00 10 00 00 8d ?? 00 00 01 13 0b 1f 0d 13 0f 38}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoBot_FAS_2147845791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.FAS!MTB"
        threat_id = "2147845791"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 09 02 8e 69 5d 02 09 02 8e 69 5d 91 07 09 07 8e 69 5d 91 61 02 09 17 d6 02 8e 69 5d 91 da 72}  //weight: 2, accuracy: High
        $x_2_2 = {0a 5d b4 9c 09 15 d6 0d 09 16 2f c1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoBot_EH_2147846473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.EH!MTB"
        threat_id = "2147846473"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RSACryptoServiceProvider" ascii //weight: 1
        $x_1_2 = "RijndaelManaged" ascii //weight: 1
        $x_1_3 = "1HoUwlxK9GgY4Qkwl2.g7UoLNI4rZCCjwZkIm" wide //weight: 1
        $x_1_4 = "d8k7CPH3JWsvFqUa3L.WMXnWvUDZxNRRuUYv3" wide //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoBot_ASCN_2147888507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.ASCN!MTB"
        threat_id = "2147888507"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 11 04 02 11 04 91 07 61 06 09 91 61 d2 9c 09 03 6f ?? 00 00 0a 17 59 fe 01 13 05 11 05 2c 04 16 0d 2b 04 09 17 58 0d 00 11 04 17 58 13 04 11 04 02 8e 69 fe 04 13 06 11 06 2d c3}  //weight: 1, accuracy: Low
        $x_1_2 = "Geometri_Odev.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoBot_BH_2147924952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.BH!MTB"
        threat_id = "2147924952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0d 09 20 00 01 00 00 6f ?? 00 00 0a 09 20 80 00 00 00 6f ?? 00 00 0a 03 07 20 30 75 00 00 73 ?? 00 00 0a 13 04 09 11 04 09 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 09 11 04 09 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 09 17 6f ?? 00 00 0a 08 09 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f}  //weight: 3, accuracy: Low
        $x_1_2 = {16 08 09 1a 28 ?? 00 00 0a 09 1a 58 0d 11 05 17 58 13 05 11 05 06 32}  //weight: 1, accuracy: Low
        $x_1_3 = "BIPew524seeyzz.iAzcxenzuyu00w" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoBot_ATFA_2147928025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoBot.ATFA!MTB"
        threat_id = "2147928025"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {38 ba 00 00 00 2b 68 72 ?? 00 00 70 38 64 00 00 00 38 69 00 00 00 38 6e 00 00 00 72 ?? 00 00 70 38 6a 00 00 00 38 6f 00 00 00 16 2d 12 16 2d 0f 38 6e 00 00 00 6f ?? 00 00 0a 0b 14 0c 2b 1c}  //weight: 3, accuracy: Low
        $x_2_2 = {07 08 16 08 8e 69 6f ?? 00 00 0a 0d de 44 06 38 ?? ff ff ff 28 ?? 00 00 0a 38 ?? ff ff ff 6f ?? 00 00 0a 38 ?? ff ff ff 06 38 ?? ff ff ff 28 ?? 00 00 0a 38 ?? ff ff ff 6f ?? 00 00 0a 38 ?? ff ff ff 06}  //weight: 2, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

