rule TrojanDownloader_MSIL_Seraph_A_2147782391_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.A!MTB"
        threat_id = "2147782391"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 1d 19 28 08 00 00 06 0a 06 19 16 28 08 00 00 06 0a 2b 22 0a 2b dc 0a 2b e6 72 01 00 00 70 06 28 06 00 00 06 8c 0d 00 00 01 28 15 00 00 0a 06 28 07 00 00 06 0a 06 28 09 00 00 06 16 fe 01 0b 07 2d d7}  //weight: 10, accuracy: High
        $x_3_2 = {fa 01 33 00 16 00 00 01 00 00 00 33 00 00 00 05 00 00 00 08 00 00 00 13 00 00 00 0b}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_A_2147782391_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.A!MTB"
        threat_id = "2147782391"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {61 d1 9d fe ?? ?? ?? 20 ?? ?? ?? ?? 20 02 ?? ?? ?? 63 20 ?? ?? ?? ?? 58 66 20 02 ?? ?? ?? 62 20 ?? ?? ?? ?? 59 66 20 ?? ?? ?? ?? 59 59 25}  //weight: 10, accuracy: Low
        $x_1_2 = "XRails" ascii //weight: 1
        $x_1_3 = "ConsoleApp" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "Activator" ascii //weight: 1
        $x_1_7 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_B_2147782462_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.B!MTB"
        threat_id = "2147782462"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 38 0e 00 00 00 20 e8 03 00 00 28 05 00 00 0a 06 17 58 0a 06 1f 16 3f ea ff ff ff 28 06 00 00 0a 14 fe 06 ?? ?? ?? 06 73 07 00 00 0a 6f 08 00 00 0a 73 ?? ?? ?? 06 25 14 fe 06 ?? ?? ?? 06 73 ?? ?? ?? 06 6f ?? ?? ?? 06 6f ?? ?? ?? 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 0b 06 07 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 0c dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_C_2147782463_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.C!MTB"
        threat_id = "2147782463"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 00 17 58 13 00 38}  //weight: 1, accuracy: High
        $x_1_2 = {11 00 1f 16 3f ?? ?? ?? ?? 38}  //weight: 1, accuracy: Low
        $x_1_3 = {16 13 00 38}  //weight: 1, accuracy: High
        $x_1_4 = {06 25 14 fe 06 ?? ?? ?? 06 73 ?? ?? ?? 06 6f ?? ?? ?? 06 6f ?? ?? ?? 06 38}  //weight: 1, accuracy: Low
        $x_1_5 = {0a 13 01 38 00 00 00 00 11 00 11 01 6f ?? ?? ?? 0a 38 00 00 00 00 11 01 ?? ?? ?? ?? ?? 72 ?? ?? ?? 70 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 13 02 38 00 00 00 00 dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_D_2147783201_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.D!MTB"
        threat_id = "2147783201"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {20 e7 03 00 00 2b 3c 00 2b 40 16 2d ee 17 59 2b 3c 18 2c 08 00 2b 39 16 fe 03 2b 37 16 2d e8 2b 35 2d dc 2b 34 2b 39 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 16 2d c4 00 1a 2c c0 07 6f ?? ?? ?? 0a 00 2a 0a 2b ba 28 ?? ?? ?? 0a 2b bd 06 2b bd 0a 2b c1 06 2b c4 0c 2b c6 08 2b c8}  //weight: 10, accuracy: Low
        $x_1_2 = "Spotify" ascii //weight: 1
        $x_1_3 = "Animals run" ascii //weight: 1
        $x_1_4 = "Humans run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_E_2147783310_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.E!MTB"
        threat_id = "2147783310"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 22 2b 27 72 ?? ?? ?? 70 2b 23 00 16 2d 04 2b 24 2b 25 00 17 25 2c 0b 16 2c 24 26 16 2d e1 2b 00 2b 1f 2a 73 ?? ?? ?? 0a 2b d7 0a 2b d6 28 ?? ?? ?? 0a 2b d6 06 2b d9 6f ?? ?? ?? 0a 2b d4 0b 2b da 07 2b de}  //weight: 10, accuracy: Low
        $x_1_2 = "Spotify" ascii //weight: 1
        $x_1_3 = "you have smart car" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_MR_2147783313_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.MR!MTB"
        threat_id = "2147783313"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {06 09 06 6f [0-4] 1e 5b 6f [0-4] 6f [0-4] 06 09 06 6f [0-4] 1e 5b 6f [0-4] 6f [0-4] 06 17 6f [0-4] 07 06 6f [0-4] 17}  //weight: 6, accuracy: Low
        $x_1_2 = "get_KeySize" ascii //weight: 1
        $x_1_3 = "set_IV" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "get_UTF8" ascii //weight: 1
        $x_1_6 = "set_BlockSize" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Seraph_SIB_2147798222_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.SIB!MTB"
        threat_id = "2147798222"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 0b 2b ?? 06 02 07 28 ?? ?? ?? ?? 03 07 03 28 ?? ?? ?? ?? 5d 28 ?? ?? ?? ?? 61 d1 28 ?? ?? ?? ?? 26 07 17 58 0b 07 02 28 ?? ?? ?? ?? 32 ?? 06 28 ?? ?? ?? ?? 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_MA_2147807757_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.MA!MTB"
        threat_id = "2147807757"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TvGOxIBD5r" ascii //weight: 1
        $x_1_2 = "Sleep" ascii //weight: 1
        $x_1_3 = "Encoding" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "Ygqvgzh" ascii //weight: 1
        $x_1_7 = "http://www.google.com/search?oe=utf8&ie=utf8..." ascii //weight: 1
        $x_1_8 = "006150e0-a4c5-4ef7-9d08-387d1909f3af" ascii //weight: 1
        $x_1_9 = "Steam" ascii //weight: 1
        $x_1_10 = "CurrentDomain" ascii //weight: 1
        $x_1_11 = "RegisterPool" ascii //weight: 1
        $x_1_12 = "TestBase" ascii //weight: 1
        $x_1_13 = "InvokeMember" ascii //weight: 1
        $x_1_14 = "responseStatus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_MB_2147808214_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.MB!MTB"
        threat_id = "2147808214"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 0d 6a 59 13 05 1f 00 09 69 8d ?? ?? ?? 01 25 17 73 ?? ?? ?? 0a 13 04 06 6f ?? ?? ?? 0a [0-8] 07 06 11 04 11 05 09 6f ?? ?? ?? 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_3 = "IsLogging" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
        $x_1_8 = "DownloadData" wide //weight: 1
        $x_1_9 = "Debugger" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "set_Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_MC_2147808964_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.MC!MTB"
        threat_id = "2147808964"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 13 03 38 ?? ?? ?? ?? fe ?? ?? ?? 45 01 00 00 00 05 00 00 00 38 ?? ?? ?? 00 11 03 13 04 38 ?? ?? ?? 00 11 02 11 03 28 ?? ?? ?? 06 38 ?? ?? ?? 00 11 03 16 6a 28 ?? ?? ?? 06 20 00 00 00 00 7e ?? 00 00 04 39 ?? ff ff ff 26 20 00 00 00 00 38 ?? ff ff ff dd 48}  //weight: 1, accuracy: Low
        $x_1_2 = "LoginIdentifier" ascii //weight: 1
        $x_1_3 = "FlushIdentifier" ascii //weight: 1
        $x_1_4 = "WYJ16LcGIj" wide //weight: 1
        $x_1_5 = "DoYouThing" ascii //weight: 1
        $x_1_6 = "costura.costura.dll.compressed" ascii //weight: 1
        $x_1_7 = "DeflateStream" ascii //weight: 1
        $x_1_8 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_MD_2147811456_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.MD!MTB"
        threat_id = "2147811456"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Reverse" ascii //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 39 00 31 00 2e 00 32 00 34 00 33 00 2e 00 34 00 34 00 2e 00 31 00 39 00 2f 00 [0-16] 2e 00 6a 00 70 00 65 00 67 00}  //weight: 1, accuracy: Low
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_ABE_2147830427_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.ABE!MTB"
        threat_id = "2147830427"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 06 6f 2b ?? ?? 0a 0d 07 09 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 02 13 04 07 6f ?? ?? ?? 0a 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 dd ?? ?? ?? 00 08 39 ?? ?? ?? 00 08 6f ?? ?? ?? 0a dc}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
        $x_1_4 = "WebResponse" ascii //weight: 1
        $x_1_5 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_ABI_2147830991_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.ABI!MTB"
        threat_id = "2147830991"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {1e 5b 6f 30 ?? ?? 0a 6f ?? ?? ?? 0a 08 17 6f ?? ?? ?? 0a 07 08 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 04 11 04 02 16 02 8e 69 6f ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a de 0c 11 04 2c 07 11 04 6f ?? ?? ?? 0a dc 07 6f ?? ?? ?? 0a 13 05 de 14}  //weight: 3, accuracy: Low
        $x_3_2 = {09 08 6f 23 ?? ?? 0a 08 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 13 04 de 0d}  //weight: 3, accuracy: Low
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_SRP_2147836805_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.SRP!MTB"
        threat_id = "2147836805"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 17 58 0d 09 20 00 01 00 00 5d 0d 11 05 11 09 09 94 58 13 05 11 05 20 00 01 00 00 5d 13 05 11 09 09 94 13 07 11 09 09 11 09 11 05 94 9e 11 09 11 05 11 07 9e 11 09 11 09 09 94 11 09 11 05 94 58 20 00 01 00 00 5d 94 13 06 08 11 04 07 11 04 91 11 06 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 9d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_ARA_2147837235_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.ARA!MTB"
        threat_id = "2147837235"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InvokeMember" ascii //weight: 1
        $x_1_2 = "WebResponse" ascii //weight: 1
        $x_1_3 = "GetResponseStream" ascii //weight: 1
        $x_2_4 = {09 11 04 08 11 04 08 8e 69 5d 91 06 11 04 91 61 d2 9c 11 04 17 58 13 04 11 04 06 8e 69 32 e1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_ARA_2147837235_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.ARA!MTB"
        threat_id = "2147837235"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 04 16 13 05 16 2d 15 2b 19 11 04 11 05 09 11 05 09 8e 69 5d 91 07 11 05 91 61 d2 9c 11 05 17 58 13 05 11 05 15 2c d3 16 2d f4 07 8e 69 32 da 11 04 13 06 de 65 28}  //weight: 2, accuracy: High
        $x_1_2 = "HttpWebRequest" ascii //weight: 1
        $x_1_3 = "WebResponse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_ABGH_2147837564_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.ABGH!MTB"
        threat_id = "2147837564"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 06 73 16 ?? ?? 0a 0b 00 73 ?? ?? ?? 0a 0c 00 07 16 73 ?? ?? ?? 0a 73 ?? ?? ?? 0a 0d 00 09 08 6f ?? ?? ?? 0a 00 00 de 0b 09 2c 07 09 6f ?? ?? ?? 0a 00 dc 08 6f ?? ?? ?? 0a 13 04 de 16 08 2c 07 08 6f ?? ?? ?? 0a 00 dc}  //weight: 2, accuracy: Low
        $x_1_2 = "Crguqvnvzkqiewxwbaecr" wide //weight: 1
        $x_1_3 = "Ujnzu.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_ABKP_2147839358_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.ABKP!MTB"
        threat_id = "2147839358"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0d 09 07 6f ?? 00 00 0a 13 04 08 11 04 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 28 ?? 00 00 06 13 05 08 6f ?? 00 00 0a 11 05 16 11 05 8e 69 6f ?? 00 00 0a 13 06 de 37 09 2c 06 09 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "TransformFinalBlock" ascii //weight: 1
        $x_1_3 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_ARAX_2147839816_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.ARAX!MTB"
        threat_id = "2147839816"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 16 2d e0 17 25 2c 07 58 13 04 11 04 07 8e 69 1b 2c f2 32 d6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_CAG_2147841121_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.CAG!MTB"
        threat_id = "2147841121"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {14 0a 2b 11 00 72 ?? 00 0f 70 28 ?? 00 00 06 0a de 03 26 de 00 06 2c ec 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 06 7e ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_CAH_2147841126_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.CAH!MTB"
        threat_id = "2147841126"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a de 03 26 de 00 06 6f ?? 00 00 0a 2c e2 28 ?? 00 00 0a 06 16 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 7e ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_CD_2147841266_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.CD!MTB"
        threat_id = "2147841266"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {28 27 00 00 0a 06 6f 28 00 00 0a 28 0c 00 00 06 7e 29 00 00 0a 6f 2a 00 00 0a 28 2b 00 00 0a 2a}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_CSTV_2147845027_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.CSTV!MTB"
        threat_id = "2147845027"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 01 00 00 70 28 ?? ?? ?? ?? 0a dd ?? ?? ?? ?? 26}  //weight: 5, accuracy: Low
        $x_1_2 = "http://80.66.75.37/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_ABNT_2147845033_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.ABNT!MTB"
        threat_id = "2147845033"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 04 06 09 06 09 8e 69 5d 91 08 06 91 61 d2 6f ?? ?? ?? 0a 06 16 2d df 17 58 0a 16 2d b7 06 08 8e 69 32 dc 11 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b 13 06 1d 2c b7}  //weight: 4, accuracy: Low
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_SR_2147845646_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.SR!MTB"
        threat_id = "2147845646"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 01 00 00 70 28 ?? ?? ?? 06 0a dd ?? ?? ?? 00 26 de ec 06 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "ReadAsByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_RI_2147848539_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.RI!MTB"
        threat_id = "2147848539"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Xmubbdczbmbspju" wide //weight: 1
        $x_1_2 = "http://justnormalsite.ddns.net" wide //weight: 1
        $x_1_3 = "$46847078-fcda-4fea-b338-4ee4578b7a59" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_RH_2147848738_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.RH!MTB"
        threat_id = "2147848738"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 0a 38 26 00 00 00 00 28 14 00 00 0a 28 23 00 00 06 6f 15 00 00 0a 28 16 00 00 0a 28 08 00 00 06 0a dd 06 00 00 00 26 dd 00 00 00 00 06 2c d7 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_PAAL_2147848840_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.PAAL!MTB"
        threat_id = "2147848840"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//vulcano-group.com/west/Zmkdlk.dat" wide //weight: 1
        $x_1_2 = "$cbe79db5-df19-4f02-baaf-054d7e47858e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_PAAM_2147848841_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.PAAM!MTB"
        threat_id = "2147848841"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PowerShell.exe" wide //weight: 1
        $x_1_2 = "\\bfsvc.exe" wide //weight: 1
        $x_1_3 = "//SS.XFILES.EU.ORG/favicon.png" ascii //weight: 1
        $x_1_4 = "/c schtasks /create /sc onlogon /tn Ctfmon /tr C:\\Windows\\ctfmon.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_AADY_2147850700_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.AADY!MTB"
        threat_id = "2147850700"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0c 1a 8d ?? 00 00 01 0d 08 09 16 1a 6f ?? 00 00 0a 26 09 16 28 ?? 00 00 0a 13 04 08 16 73 ?? 00 00 0a 13 05 11 04 8d ?? 00 00 01 13 06 11 05 11 06 16 11 04 6f ?? 00 00 0a 26 11 06 13 07 de 16 11 05 2c 07 11 05 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "ReadAsByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_AAEZ_2147850716_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.AAEZ!MTB"
        threat_id = "2147850716"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 16 06 7b ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 0a 7e ?? 00 00 04 25 3a ?? 00 00 00 26 7e ?? 00 00 04 fe ?? ?? 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 06 fe ?? ?? 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 7e ?? 00 00 04 25}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_AAFS_2147850992_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.AAFS!MTB"
        threat_id = "2147850992"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0a 06 20 00 01 00 00 6f ?? 00 00 0a 06 7e ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 7e ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 14 0c}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_AAGH_2147851143_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.AAGH!MTB"
        threat_id = "2147851143"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 72 15 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 6f 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 28 ?? 00 00 06 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05 dd ?? 00 00 00 09 39 ?? 00 00 00 09 6f ?? 00 00 0a dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_SU_2147851336_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.SU!MTB"
        threat_id = "2147851336"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 2b 06 16 2c 0a 26 de 0d 28 ?? ?? ?? 06 2b f3 0c 2b f4 26 de 00 08 2c e7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_SU_2147851336_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.SU!MTB"
        threat_id = "2147851336"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 72 8d 00 00 70 6f 0d 00 00 0a 6f 0e 00 00 0a 6f 0f 00 00 0a 6f 10 00 00 0a 6f 11 00 00 0a 13 04 dd 0f 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_AAGV_2147851443_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.AAGV!MTB"
        threat_id = "2147851443"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 02 16 28 ?? 00 00 06 13 03 20 01 00 00 00 7e ?? 03 00 04 7b ?? 02 00 04 39 ?? ff ff ff 26 20 00 00 00 00 38 ?? ff ff ff 11 0b 11 02 16 1a 6f ?? 00 00 0a 26 20 00 00 00 00 7e ?? 03 00 04 7b ?? 03 00 04 3a ?? ff ff ff 26 20 00 00 00 00 38 ?? ff ff ff 11 0b 16 73 ?? 00 00 0a 13 09 20 03 00 00 00 7e ?? 03 00 04 7b ?? 03 00 04 39 ?? ff ff ff 26 20 01 00 00 00 38}  //weight: 2, accuracy: Low
        $x_1_2 = "DnsClient.Shared.GlobalMap.resources" ascii //weight: 1
        $x_1_3 = "botnetlogs.com/PureCrypter/panel/uploads/Pwaeno.vdf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_CXGG_2147851579_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.CXGG!MTB"
        threat_id = "2147851579"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 6c 00 65 00 61 00 6e 00 69 00 6e 00 67 00 2e 00 68 00 6f 00 6d 00 65 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 70 00 63 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_SV_2147851871_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.SV!MTB"
        threat_id = "2147851871"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 04 00 00 06 13 04 09 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 13 05 dd 27 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_SV_2147851871_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.SV!MTB"
        threat_id = "2147851871"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0d 6f 03 00 00 0a 13 25 11 0c 11 25 11 15 59 61 13 0c 11 15 19 11 0c 58 1e 63 59 13 15 11 0d 6f 37 00 00 06 2d d9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_SV_2147851871_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.SV!MTB"
        threat_id = "2147851871"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 08 09 06 09 91 7e 01 00 00 04 59 d2 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d e1}  //weight: 2, accuracy: High
        $x_2_2 = "Gnfojaeqjl.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_ABNN_2147896457_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.ABNN!MTB"
        threat_id = "2147896457"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0d 09 08 6f ?? ?? ?? 0a de 07 09 6f ?? ?? ?? 0a dc 08 6f ?? ?? ?? 0a 13 04 de 0e 27 00 07 16 73 ?? ?? ?? 0a 73}  //weight: 3, accuracy: Low
        $x_1_2 = "GetType" ascii //weight: 1
        $x_1_3 = "GetResponseStream" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_ABES_2147896492_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.ABES!MTB"
        threat_id = "2147896492"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b 1c 12 03 2b 1b 2b 20 02 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a de 17 08 2b e1 28 ?? ?? ?? 0a 2b de 06 2b dd}  //weight: 3, accuracy: Low
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "GetDomain" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_ABFI_2147896494_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.ABFI!MTB"
        threat_id = "2147896494"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 2b 2e 2b 33 2b 38 16 2d 09 2b 09 2b 0a 6f ?? ?? ?? 0a de 10 08 2b f4 07 2b f3 08 2c 06 08 6f ?? ?? ?? 0a dc 07 6f ?? ?? ?? 0a 0d de 2e 06 2b cf}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "Smsnnzapzbqxq" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_ASE_2147898078_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.ASE!MTB"
        threat_id = "2147898078"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 16 6f ?? 00 00 0a 13 06 12 06 28 ?? 00 00 0a 13 07 11 04 11 07 6f ?? 00 00 0a 11 05 17 58 13 05 11 05 09 6f ?? 00 00 0a 32 d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_SW_2147898861_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.SW!MTB"
        threat_id = "2147898861"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 73 01 00 00 0a 72 01 00 00 70 28 02 00 00 0a 6f 03 00 00 0a 0a 06 8e 69 8d 04 00 00 01 0b 16 0c 06 8e 69 17 59 0d 38 0e 00 00 00 07 08 06 09 91 9c 08 17 58 0c 09 17 59 0d 09 16 2f ee 07 13 04 dd 03 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_PAQ_2147899472_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.PAQ!MTB"
        threat_id = "2147899472"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "grabpflege-ettlingen.de/wps/loader/uploads/" ascii //weight: 1
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "GetResponseStream" ascii //weight: 1
        $x_1_4 = "MemoryStreamWrite" ascii //weight: 1
        $x_1_5 = "Football" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_ARBD_2147899494_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.ARBD!MTB"
        threat_id = "2147899494"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 09 18 5b 06 09 18 6f 17 00 00 0a 1f 10 28 18 00 00 0a 9c 09 18 58 0d 09 07 32 e4}  //weight: 5, accuracy: High
        $x_5_2 = "http://mosiadomneasca.ro/wp-includes/" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_SX_2147901246_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.SX!MTB"
        threat_id = "2147901246"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 7b 04 00 00 04 03 04 58 06 58 6f 13 00 00 06 06 17 58 0a 06 1b 32 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_CCHZ_2147906460_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.CCHZ!MTB"
        threat_id = "2147906460"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 0b 2b 10 de 14 73 ?? ?? ?? 0a 2b ee 28 ?? 00 00 0a 2b ee 0a 2b ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Seraph_AFUA_2147941593_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seraph.AFUA!MTB"
        threat_id = "2147941593"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 73 ?? 00 00 0a 13 05 11 05 11 04 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 06 11 06 06 16 06 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 03 11 05 6f ?? 00 00 0a 6f ?? 00 00 06 17 0b de 45}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

