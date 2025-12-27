rule TrojanDownloader_MSIL_AgentTesla_A_2147731535_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.A!MTB"
        threat_id = "2147731535"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "011010010110111001101010010100100111010101101110" wide //weight: 3
        $x_1_2 = "GetEnvironmentVariable" wide //weight: 1
        $x_1_3 = "_ENABLE_PROFILING" wide //weight: 1
        $x_1_4 = "X0VOQUJMRV9QUk9GSUxJTkc=" wide //weight: 1
        $x_1_5 = "R2V0RW52aXJvbm1lbnRWYXJpYWJsZQ==" wide //weight: 1
        $x_1_6 = "http://bit.ly/" wide //weight: 1
        $x_1_7 = "ConfuserEx v1.0.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_ND_2147777022_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ND!MTB"
        threat_id = "2147777022"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SpdReaderWriterGuiLoader" ascii //weight: 1
        $x_1_2 = "spdrwguildr" ascii //weight: 1
        $x_1_3 = "GzipMethod" ascii //weight: 1
        $x_1_4 = "$88e14e21-0ade-460a-9cb7-63255f1c4078" ascii //weight: 1
        $x_1_5 = "get_spdrwgui_exe" ascii //weight: 1
        $x_1_6 = "A213M" ascii //weight: 1
        $x_1_7 = "2.22.11.11" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_NQ_2147777570_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.NQ!MTB"
        threat_id = "2147777570"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 05 00 00 0a 0c 00 07 16 73 06 00 00 0a 73 07 00 00 0a 0d 00 09 08 6f 08 00 00 0a 00 00 de 0b}  //weight: 1, accuracy: High
        $x_1_2 = {95 a2 29 09 0b 00 00 00 da a4 21 00 16 00 00 01 00 00 00 39 00 00 00 08 00 00 00 06 00 00 00 12 00 00 00 04 00 00 00 39 00 00 00 18 00 00 00 01 00 00 00 07 00 00 00 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_NS_2147777696_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.NS!MTB"
        threat_id = "2147777696"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cdn.discordapp.com/attachments/" ascii //weight: 10
        $x_1_2 = "Khdjvwjdtqrymmqbudp.Zsnmdviewswsfojks" ascii //weight: 1
        $x_1_3 = "Fzzyhjlxmatragttprvjqyx.Lnydjnlnrdgnolnao" ascii //weight: 1
        $x_1_4 = "Reqwgdalckljtvgwjtjwexax.Aamtvsxqeb" ascii //weight: 1
        $x_1_5 = "Toairbnwmoksarjexj.Vfiozsrttxhfjelvfpiwltx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_NY_2147777949_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.NY!MTB"
        threat_id = "2147777949"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 15 a2 0b 09 0b 00 00 00 10 00 03 00 02 00 00 01 00 00 00 42 00 00 00 0a 00 00 00 08 00 00 00 15 00 00 00 05 00 00 00 48 00 00 00 18 00 00 00 08 00 00 00 03 00 00 00 04 00 00 00 05 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 05 00 00 00 01 00 00 00 01 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_STB_2147780285_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.STB"
        threat_id = "2147780285"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".ml/liverpool-fc-news/features/steven-gerrard" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_CVX_2147794301_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.CVX!MTB"
        threat_id = "2147794301"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {68 00 74 00 00 07 74 00 70 00 73 00 00 0b 3a 00 2f 00 2f 00 70 00 61 00 00 09 73 00 74 00 65 00 62 00 00 07 69 00 6e 00 2e 00 00 0b 70 00 6c 00 2f 00 76 00 69 00 00 09 65 00 77 00 2f 00 72 00 00 09 61 00 77 00 2f 00 61 00 00 05 65 00 34 00 00 03}  //weight: 10, accuracy: High
        $x_10_2 = {68 00 74 00 74 00 00 05 70 00 73 00 00 0b 70 00 61 00 73 00 74 00 65 00 00 0d 62 00 69 00 6e 00 2e 00 70 00 6c 00 00 05 76 00 69 00 00 05 65 00 77 00 00 03 72 00 00 05 61 00 77 00 00 05 38 00 61 00}  //weight: 10, accuracy: High
        $x_1_3 = {00 54 6f 43 68 61 72 00}  //weight: 1, accuracy: High
        $x_1_4 = "GetExportedTypes" ascii //weight: 1
        $x_1_5 = "ToInt32" ascii //weight: 1
        $x_1_6 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_JTN_2147794503_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.JTN!MTB"
        threat_id = "2147794503"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fsFSsfasSA22W" ascii //weight: 1
        $x_1_2 = "afcSDwdsad21HR0cHM6" ascii //weight: 1
        $x_1_3 = "fcSDwdsad21" ascii //weight: 1
        $x_1_4 = "cdsSDADsaw2" ascii //weight: 1
        $x_1_5 = "sdgafadgg4tgS" ascii //weight: 1
        $x_1_6 = "jJASHJ24" ascii //weight: 1
        $x_1_7 = "Mmvdaskk3df32" ascii //weight: 1
        $x_1_8 = "cmd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_JUA_2147794770_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.JUA!MTB"
        threat_id = "2147794770"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Test-NetConnection -TraceRoute" ascii //weight: 10
        $x_1_2 = "https://store2.gofile.io/download/" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "powershell" ascii //weight: 1
        $x_1_5 = "GetString" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
        $x_1_7 = "bing" ascii //weight: 1
        $x_1_8 = "InvokeMember" ascii //weight: 1
        $x_1_9 = "Debug Mode!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_JVC_2147795099_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.JVC!MTB"
        threat_id = "2147795099"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://store2.gofile.io/download/" ascii //weight: 1
        $x_1_2 = {44 00 65 00 62 00 75 00 67 00 00 09 4d 00 6f 00 64 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "GetString" ascii //weight: 1
        $x_1_4 = "Replace" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_JZQ_2147795411_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.JZQ!MTB"
        threat_id = "2147795411"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "000webhostapp.com/RunPE.dll" ascii //weight: 1
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "RunPE.RunPE" ascii //weight: 1
        $x_1_5 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_JZR_2147795412_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.JZR!MTB"
        threat_id = "2147795412"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Start-Sleep -s 5" wide //weight: 1
        $x_1_2 = "WaitForExit" ascii //weight: 1
        $x_1_3 = "Test" ascii //weight: 1
        $x_1_4 = "ShowWindow" ascii //weight: 1
        $x_1_5 = "powershell" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "GetString" ascii //weight: 1
        $x_1_8 = "Replace" ascii //weight: 1
        $x_1_9 = "GetCurrentProcess" ascii //weight: 1
        $x_1_10 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_DBJ_2147795721_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.DBJ!MTB"
        threat_id = "2147795721"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sy!stem.Refl!ection.As!sembly" wide //weight: 1
        $x_1_2 = "https://store2.gofile.io/download/" wide //weight: 1
        $x_1_3 = {00 47 65 74 54 79 70 65 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 44 6f 77 6e 6c 6f 61 64 44 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 47 65 74 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 52 65 70 6c 61 63 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 49 6e 76 6f 6b 65 4d 65 6d 62 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_JXH_2147795864_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.JXH!MTB"
        threat_id = "2147795864"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://store2.gofile.io/download/" ascii //weight: 1
        $x_1_2 = "GetString" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_LCB_2147796827_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.LCB!MTB"
        threat_id = "2147796827"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 00 63 00 65 00 64 00 62 00 38 00 62 00 66 00 2f 00 77 00 61 00 72 00 2f 00 77 00 65 00 69 00 76 00 2f 00 6c 00 70 00 2e 00 6e 00 69 00 62 00 65 00 74 00 73 00 61 00 70 00 2f 00 2f 00 3a 00 73 00 70 00 74 00 74 00 68}  //weight: 1, accuracy: High
        $x_1_2 = "StrReverse" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "GetObjectValue" ascii //weight: 1
        $x_1_5 = "DownloadString" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "Contains" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_LIN_2147798335_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.LIN!MTB"
        threat_id = "2147798335"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://179.43.187.131/ueyt/" ascii //weight: 1
        $x_1_2 = "GetType" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "WebClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_LLB_2147799001_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.LLB!MTB"
        threat_id = "2147799001"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@179.43.187.131@" ascii //weight: 1
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_LPD_2147805115_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.LPD!MTB"
        threat_id = "2147805115"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VVYUYDUYFUFHHJFJ" ascii //weight: 1
        $x_1_2 = "000webhostapp.com" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "v4.0.30319\\thedevilcoder.exe" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
        $x_1_7 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_DNO_2147805395_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.DNO!MTB"
        threat_id = "2147805395"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegSvcs" wide //weight: 1
        $x_1_2 = "000webhostapp.com" wide //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "RUNNNN" wide //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
        $x_1_7 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_LQS_2147805737_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.LQS!MTB"
        threat_id = "2147805737"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://buysrilankan.lk/pp/ConsoleApp" ascii //weight: 1
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "GetTypes" ascii //weight: 1
        $x_1_5 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_LSD_2147807578_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.LSD!MTB"
        threat_id = "2147807578"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$c27a2ae3-1cf3-473b-8f74-7d84fdeced17" ascii //weight: 1
        $x_1_2 = "SuspendLayout" ascii //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
        $x_1_4 = "ColorTranslator" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_LTB_2147807794_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.LTB!MTB"
        threat_id = "2147807794"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://buysrilankan.lk/pp/ConsoleApp" ascii //weight: 1
        $x_1_2 = "GetMethod" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
        $x_1_6 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_LUU_2147808669_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.LUU!MTB"
        threat_id = "2147808669"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://buysrilankan.lk/k/ConsoleApp" ascii //weight: 1
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "GetMethod" ascii //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_NCB_2147810497_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.NCB!MTB"
        threat_id = "2147810497"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 [0-2] 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73}  //weight: 1, accuracy: Low
        $x_1_2 = "GetTypeFromHandle" ascii //weight: 1
        $x_1_3 = "DxownxloxadDxatxxax" ascii //weight: 1
        $x_1_4 = "Replace" ascii //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
        $x_1_7 = "Reverse" ascii //weight: 1
        $x_1_8 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_NHS_2147812346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.NHS!MTB"
        threat_id = "2147812346"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "61"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 00 70 00 6c 00 6f 00 6f 00 64 00 65 00 72 00 2e 00 6e 00 65 00 74 00 2f 00 69 00 6d 00 67 00 2f 00 69 00 6d 00 61 00 67 00 65 00 2f 00 [0-112] 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {75 70 6c 6f 6f 64 65 72 2e 6e 65 74 2f 69 6d 67 2f 69 6d 61 67 65 2f [0-112] 2e 70 6e 67}  //weight: 1, accuracy: Low
        $x_1_3 = {75 00 70 00 6c 00 6f 00 6f 00 64 00 65 00 72 00 2e 00 6e 00 65 00 74 00 2f 00 69 00 6d 00 67 00 2f 00 69 00 6d 00 61 00 67 00 65 00 2f 00 [0-112] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_4 = {75 70 6c 6f 6f 64 65 72 2e 6e 65 74 2f 69 6d 67 2f 69 6d 61 67 65 2f [0-112] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_10_5 = {44 00 6f 00 77 00 ?? ?? ?? ?? ?? ?? ?? ?? 6e 00 6c 00 ?? ?? ?? ?? ?? ?? ?? ?? 6f 00 61 00 64 00 44 00 ?? ?? ?? ?? ?? ?? ?? ?? 61 00 74 00 61 00}  //weight: 10, accuracy: Low
        $x_10_6 = "GetMethod" ascii //weight: 10
        $x_10_7 = "Replace" ascii //weight: 10
        $x_10_8 = "Invoke" ascii //weight: 10
        $x_10_9 = "WebClient" ascii //weight: 10
        $x_10_10 = "GetType" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_EFZ_2147812368_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.EFZ!MTB"
        threat_id = "2147812368"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 20 00 0c 00 00 28 ?? ?? ?? 0a 00 00 de 05}  //weight: 1, accuracy: Low
        $x_1_2 = {44 00 6f 00 77 00 ?? ?? ?? ?? ?? ?? ?? ?? 6e 00 6c 00 ?? ?? ?? ?? ?? ?? ?? ?? 6f 00 61 00 64 00 44 00 ?? ?? ?? ?? ?? ?? ?? ?? 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_3 = {00 47 65 74 4d 65 74 68 6f 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 52 65 70 6c 61 63 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 49 6e 76 6f 6b 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 57 65 62 43 6c 69 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 47 65 74 54 79 70 65}  //weight: 1, accuracy: High
        $x_1_8 = {00 73 65 74 5f 53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_EFY_2147812797_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.EFY!MTB"
        threat_id = "2147812797"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {44 00 6f 00 77 00 ?? ?? ?? ?? ?? ?? ?? ?? 6e 00 6c 00 ?? ?? ?? ?? ?? ?? ?? ?? 6f 00 61 00 64 00 44 00 ?? ?? ?? ?? ?? ?? ?? ?? 61 00 74 00 61 00}  //weight: 10, accuracy: Low
        $x_10_2 = {47 00 65 00 74 00 42 00 79 00 ?? ?? ?? ?? ?? ?? ?? ?? 74 00 65 00 41 00 72 00 72 00 ?? ?? ?? ?? ?? ?? ?? ?? 61 00 79 00 41 00 73 00 79 00 ?? ?? ?? ?? ?? ?? ?? ?? 6e 00 63 00}  //weight: 10, accuracy: Low
        $x_1_3 = {00 47 65 74 4d 65 74 68 6f 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 52 65 70 6c 61 63 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 49 6e 76 6f 6b 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 47 65 74 54 79 70 65}  //weight: 1, accuracy: High
        $x_1_7 = {00 57 65 62 43 6c 69 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 48 74 74 70 43 6c 69 65 6e 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_EGA_2147812798_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.EGA!MTB"
        threat_id = "2147812798"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {7b 00 22 00 73 00 74 00 61 00 74 00 75 00 73 00 22 00 3a 00 74 00 72 00 75 00 65 00 2c 00 22 00 64 00 61 00 74 00 61 00 22 00 3a 00 30 00 2e 00 30 00 30 00 30 00 30 00 34 00 31 00 33 00 30 00 32 00 34 00 34 00 39 00 32 00 35 00 38 00 35 00 36 00 34 00 7d}  //weight: 10, accuracy: High
        $x_10_2 = {00 53 65 72 69 61 6c 69 7a 65 72 00}  //weight: 10, accuracy: High
        $x_1_3 = {00 47 65 74 4d 65 74 68 6f 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 52 65 70 6c 61 63 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 49 6e 76 6f 6b 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 47 65 74 54 79 70 65}  //weight: 1, accuracy: High
        $x_1_7 = {00 57 65 62 43 6c 69 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 48 74 74 70 43 6c 69 65 6e 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_NLQ_2147813551_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.NLQ!MTB"
        threat_id = "2147813551"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 00 42 00 64 00 4f 00 36 00 4e 00 77 00 49 00 50 00 70 00 6d 00 4d 00 5a 00 4e 00 44 00 4a 00 41 00 73 00 44 00 67 00 63 00 51 00 3d}  //weight: 1, accuracy: High
        $x_1_2 = {74 00 76 00 39 00 55 00 41 00 66 00 2f 00 57 00 6a 00 59 00 42 00 4f 00 46 00 2b 00 52 00 65 00 67 00 70 00 65 00 76 00 63 00 49 00 6a 00 64 00 64 00 6c 00 4f 00 4d 00 67 00 57 00 77 00 34 00 32 00 58 00 6c 00 46 00 31 00 4d 00 51 00 51 00 6d 00 4e}  //weight: 1, accuracy: High
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "vpx3x.Properties.YtTh1" ascii //weight: 1
        $x_1_5 = "StylusLogic" ascii //weight: 1
        $x_1_6 = "InvokeMember" ascii //weight: 1
        $x_1_7 = "vpx3x;component/mainwindow.xaml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_NLR_2147813552_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.NLR!MTB"
        threat_id = "2147813552"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kotadiainc.com/Jriww.png" ascii //weight: 1
        $x_1_2 = "ReverserData" ascii //weight: 1
        $x_1_3 = {2f 00 63 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 32 00 30}  //weight: 1, accuracy: High
        $x_1_4 = {52 00 65 00 76 00 65 00 72 00 73 00 65 00 00 07 63 00 6d 00 64}  //weight: 1, accuracy: High
        $x_1_5 = {44 00 78 00 79 00 72 00 6d 00 63 00 68 00 62 00 71 00 76 00 6a 00 71 00 76 00 6b 00 72 00 6c 00 66 00 68 00 61 00 75 00 6e 00 67 00 61 00 7a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_NLS_2147813579_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.NLS!MTB"
        threat_id = "2147813579"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "71"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 16 00 00 0a 25 72 01 00 00 70 6f 17 00 00 0a 00 25 72 09 00 00 70 6f 18 00 00 0a 00 25 17 6f 19 00 00 0a 00 28 1a 00 00 0a 26 23 00 00 00 00 00 00 34 40 28 1b 00 00 0a 28 1c 00 00 0a 00 2a}  //weight: 10, accuracy: High
        $x_10_2 = {28 03 00 00 06 00 28 04 00 00 06 00 28 06 00 00 06 26 16 0a 2b 00 06 2a}  //weight: 10, accuracy: High
        $x_10_3 = "91.243.44.1" ascii //weight: 10
        $x_10_4 = "Reverse" ascii //weight: 10
        $x_10_5 = "GetMethod" ascii //weight: 10
        $x_10_6 = "GetTypes" ascii //weight: 10
        $x_10_7 = "Internet" ascii //weight: 10
        $x_1_8 = "Nwhbmkdgjvwtcudswv" ascii //weight: 1
        $x_1_9 = "Viafrbkwyy" ascii //weight: 1
        $x_1_10 = "Ivdmdxewir" ascii //weight: 1
        $x_1_11 = "Zipuvmvkmgwtxwhdyvxlppk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_NLT_2147813580_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.NLT!MTB"
        threat_id = "2147813580"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 16 00 00 0a 72 01 00 00 70 17 8d 14 00 00 01 25 16 d0 23 00 00 01 28 16 00 00 0a a2 28 17 00 00 0a 14 17 8d 11 00 00 01 25 16 20 10 27 00 00 8c 23 00 00 01 a2 6f 18}  //weight: 10, accuracy: High
        $x_10_2 = "infinity-cheats.org/" ascii //weight: 10
        $x_10_3 = "GetMethods" ascii //weight: 10
        $x_10_4 = "ToInt32" ascii //weight: 10
        $x_10_5 = "Helper" ascii //weight: 10
        $x_1_6 = "Lhwaghsyrcetsylt.Kiwlulcpmmshh" ascii //weight: 1
        $x_1_7 = "Suyehdmfjayr.Atcezcoqa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_NLU_2147813581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.NLU!MTB"
        threat_id = "2147813581"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 1c 00 00 0a 25 72 11 00 00 70 6f 1d 00 00 0a 00 25 72 19 00 00 70 6f 1e 00 00 0a 00 25 17 6f 1f 00 00 0a 00 0a 2b 00 06 2a}  //weight: 10, accuracy: High
        $x_10_2 = {d0 21 00 00 01 28 19 00 00 0a 72 01 00 00 70 17 8d 14 00 00 01 25 16 d0 21 00 00 01 28 19 00 00 0a a2 28 1a 00 00 0a 14 17 8d 10 00 00 01 25 16 02 50 a2 6f 1b 00 00 0a 26 2a}  //weight: 10, accuracy: High
        $x_10_3 = "ReverserData" ascii //weight: 10
        $x_10_4 = "GetMethods" ascii //weight: 10
        $x_10_5 = "BringTop" ascii //weight: 10
        $x_1_6 = "Sazwlsquuolhwordff.Aehdzuhwyvotk" ascii //weight: 1
        $x_1_7 = "Ftqjogdi.Cfqgqof" ascii //weight: 1
        $x_1_8 = "Pqfnbdv.Yyfyodoenbg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_N_2147815195_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.N!MTB"
        threat_id = "2147815195"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$1480959e-5bf1-4215-b21e-ca78cf0af266" ascii //weight: 1
        $x_1_2 = "Cubin.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "GetType" ascii //weight: 1
        $x_1_8 = "GetExecutingAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_NPW_2147815579_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.NPW!MTB"
        threat_id = "2147815579"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bus_ticket.Properties.Resources.resources" ascii //weight: 1
        $x_1_2 = "SASAWDSAFSAFWQFWQ" ascii //weight: 1
        $x_1_3 = "FSA.FSA" ascii //weight: 1
        $x_1_4 = "WGEWGWE" ascii //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
        $x_1_6 = "GetMethod" ascii //weight: 1
        $x_1_7 = "DownloadData" ascii //weight: 1
        $x_1_8 = "GFFQFWQFWQFWQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_NPY_2147815580_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.NPY!MTB"
        threat_id = "2147815580"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "selif/moc.01-nioc-nioc-elif//:ptth" ascii //weight: 10
        $x_10_2 = "/teg/hs.refsnart//:sptth" ascii //weight: 10
        $x_1_3 = "GFFQFFDSFWQFWQFWQ" ascii //weight: 1
        $x_1_4 = "DWQDWQDQWDQWDWQDQW" ascii //weight: 1
        $x_1_5 = "Nono.Nono" ascii //weight: 1
        $x_1_6 = "DownloadData" ascii //weight: 1
        $x_1_7 = "GetMethod" ascii //weight: 1
        $x_1_8 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_EOQ_2147816162_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.EOQ!MTB"
        threat_id = "2147816162"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 02 50 08 91 8c ?? ?? ?? 01 6f ?? ?? ?? 0a 26 00 08 25 17 59 0c 16 fe 02 0d 09 2d}  //weight: 1, accuracy: Low
        $x_1_2 = "/c ping google.com && timeout 10" wide //weight: 1
        $x_1_3 = {00 47 65 74 4d 65 74 68 6f 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 47 65 74 54 79 70 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_EOR_2147816163_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.EOR!MTB"
        threat_id = "2147816163"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 04 16 20 00 04 00 00 6f ?? ?? ?? 0a 13 05 07 11 04 16 11 05 6f ?? ?? ?? 0a 00 00 11 05 16 fe 02 13 06 11 06 2d d7}  //weight: 1, accuracy: Low
        $x_1_2 = {07 06 08 91 6f ?? ?? ?? 0a 00 00 08 25 17 59 0c 16 fe 02 0d 09 2d e8}  //weight: 1, accuracy: Low
        $x_1_3 = {00 47 65 74 4d 65 74 68 6f 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_EOT_2147816180_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.EOT!MTB"
        threat_id = "2147816180"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 02 07 91 6f ?? ?? ?? 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08 2d e8}  //weight: 1, accuracy: Low
        $x_1_2 = {09 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 07 11 04 16 11 05 6f ?? ?? ?? 0a 00 00 11 05 16 fe 02 13 06 11 06 2d d8}  //weight: 1, accuracy: Low
        $x_1_3 = "/c timeout 15" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_EPY_2147816768_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.EPY!MTB"
        threat_id = "2147816768"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JOKERBLADEE.BLAZE" wide //weight: 1
        $x_1_2 = "BLAZEBLAZE" wide //weight: 1
        $x_1_3 = "transfer.sh" wide //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
        $x_1_6 = "HttpWebRequest" ascii //weight: 1
        $x_1_7 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_EPZ_2147816769_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.EPZ!MTB"
        threat_id = "2147816769"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 08 91 6f ?? ?? ?? 0a 08 25 17 59 0c 16 fe 02 0d 09 2d eb}  //weight: 1, accuracy: Low
        $x_1_2 = {06 11 04 16 11 05 6f ?? ?? ?? 0a 08 11 04 16 09 6f ?? ?? ?? 0a 25 13 05 16 fe 03 13 07 11 07 2d df}  //weight: 1, accuracy: Low
        $x_1_3 = "45.137.22.163" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_EQD_2147816907_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.EQD!MTB"
        threat_id = "2147816907"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 08 91 6f ?? ?? ?? 0a 08 25 17 59 0c 16 fe 02 0d 09 2d eb}  //weight: 1, accuracy: Low
        $x_1_2 = {06 11 04 16 11 05 6f ?? ?? ?? 0a 08 11 04 16 09 6f ?? ?? ?? 0a 25 13 05 16 fe 03 13 07 11 07 2d df}  //weight: 1, accuracy: Low
        $x_1_3 = "HttpWebRequest" ascii //weight: 1
        $x_1_4 = "HttpWebResponse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_EQE_2147816909_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.EQE!MTB"
        threat_id = "2147816909"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 03 07 91 6f ?? ?? ?? 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08 2d e8}  //weight: 1, accuracy: Low
        $x_1_2 = {11 04 11 08 16 11 09 6f ?? ?? ?? 0a 00 00 11 06 11 08 16 11 07 6f ?? ?? ?? 0a 25 13 09 16 fe 03 13 0a 11 0a 2d d9}  //weight: 1, accuracy: Low
        $x_1_3 = "HttpWebRequest" ascii //weight: 1
        $x_1_4 = "HttpWebResponse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_EQO_2147817192_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.EQO!MTB"
        threat_id = "2147817192"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 8e 69 8d ?? ?? ?? 01 13 0a 11 09 11 0a 16 11 0a 8e 69 6f ?? ?? ?? 0a 13 0b 11 08 6f ?? ?? ?? 0a 11 09 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 11 0a 16}  //weight: 1, accuracy: Low
        $x_1_2 = "U$$vX+xly" wide //weight: 1
        $x_1_3 = "DownloadFileAsync" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "FromBase64" ascii //weight: 1
        $x_1_6 = "cipherText" ascii //weight: 1
        $x_1_7 = "passPhrase" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_EQQ_2147817285_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.EQQ!MTB"
        threat_id = "2147817285"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 93 28 ?? ?? ?? ?? ?? 59 0c 20 ff ff 00 00 08 2f 0a 08 20 ff ff 00 00 59 0c 2b 0c 16 08 31 08 08 20 ff ff 00 00 58 0c 06 07 08 d1 9d 07 17 58 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_EQA_2147817417_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.EQA!MTB"
        threat_id = "2147817417"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "45.137.22.163" wide //weight: 1
        $x_1_2 = "HttpWebRequest" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
        $x_1_6 = "HttpWebResponse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_EQR_2147817419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.EQR!MTB"
        threat_id = "2147817419"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 08 91 6f ?? ?? ?? 0a 08 25 17 59 0c 16 fe 02 0d 09}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 12 00 23 00 00 00 00 00 00 34 40 28}  //weight: 1, accuracy: High
        $x_1_3 = {00 44 6f 77 6e 6c 6f 61 64 44 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 47 65 74 4d 65 74 68 6f 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_CC_2147817572_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.CC!MTB"
        threat_id = "2147817572"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iplogger.org/1xe2x7" wide //weight: 1
        $x_1_2 = "f0508564.xsph.ru/libXOR.fgredfs" wide //weight: 1
        $x_1_3 = "a0641729.xsph.ru/jirmzrWM1.exe" wide //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ERE_2147817635_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ERE!MTB"
        threat_id = "2147817635"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 08 91 6f ?? ?? ?? 0a 00 00 08 25 17 59 0c 16 fe 02 0d 09}  //weight: 1, accuracy: Low
        $x_1_2 = {0b 12 01 23 00 00 00 00 00 00 34 40 28 ?? ?? ?? 0a 0a 06}  //weight: 1, accuracy: Low
        $x_1_3 = {0b 06 07 16 07 8e 69 6f ?? ?? ?? 0a 00 06 0c 0a 00 73 ?? ?? ?? 06 28 ?? ?? ?? 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ERG_2147817660_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ERG!MTB"
        threat_id = "2147817660"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 08 91 6f ?? ?? ?? 0a 00 00 08 25 17 59 0c 16 fe 02 0d 09}  //weight: 1, accuracy: Low
        $x_1_2 = {13 05 12 05 23 00 00 00 00 00 00 24 40 28 ?? ?? ?? 0a 0b 28 ?? ?? ?? 0a 13 05 12 05 23 00 00 00 00 00 00 24 40 28 ?? ?? ?? 0a 0b}  //weight: 1, accuracy: Low
        $x_1_3 = {0a 0c 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d 09 06 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 09 00 73 ?? ?? ?? 0a 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_NSW_2147817689_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.NSW!MTB"
        threat_id = "2147817689"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":^^^^^####^^^^^####bluecovertrading.com/s/" ascii //weight: 1
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "RRUUNNN" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
        $x_1_6 = "YEWHSHJSJUISYUS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ERJ_2147817804_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ERJ!MTB"
        threat_id = "2147817804"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 07 06 08 91 6f ?? ?? ?? 0a 00 00 08 25 17 59 0c 16 fe 02 0d 09}  //weight: 1, accuracy: Low
        $x_1_2 = {20 00 0c 00 00 28 ?? ?? ?? 0a 00 00 de 05 26 00 00 de 00 73 ?? ?? ?? 0a 03 73 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 2b 00 06 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_CB_2147817827_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.CB!MTB"
        threat_id = "2147817827"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "tiny.one/4h8djec4" wide //weight: 2
        $x_2_2 = "zzzip.tiny.us/02232amax" wide //weight: 2
        $x_2_3 = "drivers.sergeydev.com/include" wide //weight: 2
        $x_2_4 = "Dknwzrdkh" wide //weight: 2
        $x_2_5 = "Ggudwtegr" wide //weight: 2
        $x_2_6 = "Nvcdgmtvexbfarjclwnzn" wide //weight: 2
        $x_1_7 = "c ping bing.com" wide //weight: 1
        $x_1_8 = "Reverse" wide //weight: 1
        $x_1_9 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_10 = "CurrentDomain" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_ERX_2147818253_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ERX!MTB"
        threat_id = "2147818253"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 13 05 2b 10 00 1c 2c cf 06 08 11 05 91 6f ?? ?? ?? 0a 00 00 11 05 25 17 59 13 05 16 25 2d fa fe 02 13 06 11 06 2d dd 06 6f ?? ?? ?? 0a 0c 08 13 07 2b 00}  //weight: 1, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ERY_2147818262_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ERY!MTB"
        threat_id = "2147818262"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 25 17 59 0c 16 2d 03 16 fe 02 16 2d 02 0d 09 2d dc 06 6f ?? ?? ?? 0a 0b 07 13 04 1c 2c e1}  //weight: 1, accuracy: Low
        $x_1_2 = {16 2d fc 20 00 0c 00 00 2b 07 00 1a 2c f2 00 de 0c 28 ?? ?? ?? 0a 2b f2}  //weight: 1, accuracy: Low
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ERZ_2147818263_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ERZ!MTB"
        threat_id = "2147818263"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0c 16 2d 12 08 06 6f ?? ?? ?? 0a 00 16 2d 07 06 6f ?? ?? ?? 0a 0d 09 13 04 17 2c f0 de 2c 02 2b d0 73 ?? ?? ?? 0a 2b cb 28 ?? ?? ?? 0a 2b c6}  //weight: 10, accuracy: Low
        $x_10_2 = {0c 08 06 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0d 09 13 04 de 0a 17 00 03 73 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 07 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a}  //weight: 10, accuracy: Low
        $x_1_3 = "/c timeout -t 15 -nobreak && ping" wide //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
        $x_1_5 = "WebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_KA_2147818439_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.KA!MTB"
        threat_id = "2147818439"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 08 13 06 16 13 07 11 06 12 07 28 1e 00 00 0a 00 08 07 11 05 18 6f 1f 00 00 0a 1f 10 28 20 00 00 0a 6f 21 00 00 0a 00 de 0d 11 07 2c 08 11 06 28 22 00 00 0a 00 dc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_KA_2147818439_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.KA!MTB"
        threat_id = "2147818439"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 25 16 72 ?? ?? ?? 70 73 ?? ?? ?? 0a a2 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 0b 07 8e}  //weight: 1, accuracy: Low
        $x_1_2 = "HttpClient" ascii //weight: 1
        $x_1_3 = "AddRange" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_KAB_2147818440_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.KAB!MTB"
        threat_id = "2147818440"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 02 28 ?? ?? ?? 06 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 00 72 ?? ?? ?? 70 0a 73}  //weight: 1, accuracy: Low
        $x_1_2 = "WebClient" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_NUA_2147818496_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.NUA!MTB"
        threat_id = "2147818496"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cdn.discordapp.com/attachments/9" ascii //weight: 10
        $x_1_2 = "Erjmmxhznmadkkxzlpimrel" ascii //weight: 1
        $x_1_3 = "Gdeidnzvlgndkacspspskpw.Uucvjiegwnd" ascii //weight: 1
        $x_1_4 = "Vsnishvwuaeiqbiv.Fkkivsrwlqjmvmkwhehr" ascii //weight: 1
        $x_1_5 = "Miyfkyaggmgt.Cvdgeznpb" ascii //weight: 1
        $x_1_6 = "Tuodqjkjkmvipasqvdrdktfm.Fgucevjuqncyqkc" ascii //weight: 1
        $x_1_7 = "Nbwomghltwhyvkknnlwv.Ovkrtdrpwteunda" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_ESG_2147818534_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ESG!MTB"
        threat_id = "2147818534"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0d 12 03 28 ?? ?? ?? 0a 23 00 00 00 00 00 00 34 40 fe 04 0c 08 08 00 00 00 06 6f ?? ?? ?? 0a}  //weight: 10, accuracy: Low
        $x_10_2 = {0c 12 02 28 ?? ?? ?? 0a 1f 14 fe 04 0b 07 08 00 00 00 06 6f ?? ?? ?? 0a}  //weight: 10, accuracy: Low
        $x_1_3 = {06 07 03 07 91 6f ?? ?? ?? 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08}  //weight: 1, accuracy: Low
        $x_1_4 = "GetMethod" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_ESI_2147818582_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ESI!MTB"
        threat_id = "2147818582"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 47 46 46 51 46 46 44 53 46 57 51 46 57 51 46 57 51 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 66 64 67 66 64 67 66 64 67 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 47 46 46 51 46 57 51 46 57 51 46 57 51 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 47 65 74 4d 65 74 68 6f 64 00 77 71 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 54 6f 43 68 61 72 41 72 72 61 79 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 44 6f 77 6e 6c 6f 61 64 44 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 47 65 74 54 79 70 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 52 65 76 65 72 73 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ESM_2147818688_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ESM!MTB"
        threat_id = "2147818688"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 11 06 9a 13 07 00 d0 ?? ?? ?? 01 28 ?? ?? ?? 0a 14 11 07 28 ?? ?? ?? 0a 13 08 11 08 16 8d ?? ?? ?? 01 6f ?? ?? ?? 0a 13 09 00 11 06 17 58}  //weight: 1, accuracy: Low
        $x_1_2 = {06 07 02 07 91 6f ?? ?? ?? 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08}  //weight: 1, accuracy: Low
        $x_1_3 = "GetMethod" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ESH_2147818842_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ESH!MTB"
        threat_id = "2147818842"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 03 07 91 6f ?? ?? ?? 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08}  //weight: 1, accuracy: Low
        $x_1_2 = "GetMethod" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ESV_2147818990_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ESV!MTB"
        threat_id = "2147818990"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 07 03 07 91 2b 18 00 2b 0b 07 25 17 59 0b 16 fe 02 0c 2b 03 00 2b f2 08 2d 02 2b 09 2b e0}  //weight: 1, accuracy: High
        $x_1_2 = "GetMethod" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ETA_2147819064_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ETA!MTB"
        threat_id = "2147819064"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dsafdasdfFDSAFADSFAS" wide //weight: 1
        $x_1_2 = {a4 e1 7c 3a 39 30 cc d4 d8 3c ad ef 56 ca b3 11 eb 55 e7 83 42 ba 4d 46 8f 82 e8 22 c4 80 6b 16 02 32 83 12 33 55 96 e2 0c 4a 33 93 de 61 47 3f}  //weight: 1, accuracy: High
        $x_1_3 = {00 44 6f 77 6e 6c 6f 61 64 44 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 47 65 74 54 79 70 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 47 65 74 4d 65 74 68 6f 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_HWMF_2147819208_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.HWMF!MTB"
        threat_id = "2147819208"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 16 00 00 00 12 00 28 ?? ?? ?? 06 38 1a 00 00 00 38 12 00 00 00 38 0d 00 00 00 00 28 ?? ?? ?? 06 13 00 38 dd ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_YRK_2147819209_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.YRK!MTB"
        threat_id = "2147819209"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "transfer.sh/get/sGdAb1/new1.jpeg" wide //weight: 1
        $x_1_2 = "leta.exe" wide //weight: 1
        $x_1_3 = "DownloadString" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "StrReverse" ascii //weight: 1
        $x_1_6 = "nigger" ascii //weight: 1
        $x_1_7 = "lempado" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ESZ_2147819237_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ESZ!MTB"
        threat_id = "2147819237"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 2c 02 2b 09 2b 0a 13 06 38 ?? ?? ?? ?? 17 2b 03 16 2b 00 2d ?? 06 6f ?? ?? ?? 0a 0d 2b 00 09 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "GetMethod" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ETP_2147819642_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ETP!MTB"
        threat_id = "2147819642"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 02 09 91 6f ?? ?? ?? 0a 2b 07 28 ?? ?? ?? 0a 2b ec}  //weight: 1, accuracy: Low
        $x_1_2 = {09 25 17 59 0d 16 fe 02 13 06 11 06 2d bd 28 ?? ?? ?? 0a 13 07 12 07 23 00 00 00 00 00 00 33 40 28 ?? ?? ?? 0a 0c 2b 02}  //weight: 1, accuracy: Low
        $x_1_3 = "SecurityProtocolType" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ETJ_2147819732_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ETJ!MTB"
        threat_id = "2147819732"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 25 17 59 0b 16 fe 02 0c 2b 03 00 2b f2 08 2d 02 2b 09 2b e0 6f ?? ?? ?? 0a 2b e1 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b 0d 2b 00 09 2a}  //weight: 10, accuracy: Low
        $x_10_2 = {06 07 02 07 91 ?? ?? ?? ?? ?? 00 00 07 25 17 59 0b 16 fe 02 0c 08 2d e7}  //weight: 10, accuracy: Low
        $x_1_3 = "SecurityProtocolType" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_ETO_2147819733_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ETO!MTB"
        threat_id = "2147819733"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 13 04 16 13 05 11 04 12 05 28 ?? ?? ?? 0a 00 07 09 02 09 91 6f ?? ?? ?? 0a 00 de 0d 11 05 2c 08 11 04 28 ?? ?? ?? 0a 00 dc 00 09 25 17 59 0d 16}  //weight: 10, accuracy: Low
        $x_1_2 = "SecurityProtocolType" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_AM_2147821601_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.AM!MTB"
        threat_id = "2147821601"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "62.197.136.64:8082/os_windows.exe" wide //weight: 1
        $x_1_2 = "PolicyRights.exe" wide //weight: 1
        $x_1_3 = "U2hhcnBaaXBMaWIuU2hhcnBSZXBvc2l0b3J5" wide //weight: 1
        $x_1_4 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
        $x_1_5 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-96] 2f 00 64 00 69 00 73 00 70 00 75 00 74 00 65 00 64 00 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_AN_2147821849_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.AN!MTB"
        threat_id = "2147821849"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bmn.lpmpbanten.id/fint" wide //weight: 2
        $x_2_2 = "rocksolidfab.ga" wide //weight: 2
        $x_2_3 = "185.222.57.155" wide //weight: 2
        $x_2_4 = "51.81.112.21" wide //weight: 2
        $x_2_5 = "sarahburrell.info/ndxzstudio/helper" wide //weight: 2
        $x_3_6 = {57 15 02 08 09 09 00 00 00 5a a4 00 00 14 00 00 01 00 00 00 2c 00 00 00 06 00 00 00 04 00 00 00}  //weight: 3, accuracy: High
        $x_1_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_8 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_AL_2147822813_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.AL!MTB"
        threat_id = "2147822813"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {09 11 04 6f 33 ?? ?? 0a 00 11 04 6f 34 ?? ?? 0a 80 10 ?? ?? 04 16 13 05 2b 1f 3c 00 72 3d ?? ?? 70 0a 06 28 2f ?? ?? 0a 0b 07 6f 30 ?? ?? 0a 0c 08 6f 31 ?? ?? 0a 0d 73 32 ?? ?? 0a 13 04}  //weight: 3, accuracy: Low
        $x_3_2 = {d2 9c 00 11 05 17 58 13 05 1e 00 7e 10 ?? ?? 04 11 05 7e 10 ?? ?? 04 11 05 91 20 70 ?? ?? 00 59}  //weight: 3, accuracy: Low
        $x_1_3 = "WebRequest" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_AO_2147822814_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.AO!MTB"
        threat_id = "2147822814"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 04 6f 1e ?? ?? 0a 00 11 04 6f 1f ?? ?? 0a 80 01 ?? ?? 04 16 13 05 2b 1f 47 00 20 00 ?? ?? 00 28 19 ?? ?? 0a 00 72 01 ?? ?? 70 0a 06 28 1a ?? ?? 0a 0b 07 6f 1b ?? ?? 0a 0c 08 6f 1c ?? ?? 0a 0d 73 1d ?? ?? 0a 13 04}  //weight: 5, accuracy: Low
        $x_1_2 = "WebResponse" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_AR_2147823783_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.AR!MTB"
        threat_id = "2147823783"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 06 8e 69 1d 2d 09 1d 00 72 73 ?? ?? 70 28 0f ?? ?? 06 1a 2d 13 26 73 43 ?? ?? 0a 1d 2d 0d}  //weight: 2, accuracy: Low
        $x_2_2 = {07 06 08 91 6f 44 ?? ?? 0a 08 25 17 59 0c 16 fe 02 0d 09 2d eb}  //weight: 2, accuracy: Low
        $x_1_3 = "WebRequest" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_AP_2147823784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.AP!MTB"
        threat_id = "2147823784"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {07 72 89 00 ?? 70 6f 16 ?? ?? 0a 20 01 ?? ?? 00 38 b8 ?? ?? ff 00 72 2a ?? ?? 70 0a 20 03 ?? ?? 00 38 a7 ?? ?? ff 38 00 ?? ?? 00 11 05 2a}  //weight: 6, accuracy: Low
        $x_6_2 = {11 05 28 0f ?? ?? 0a 13 06 72 01 ?? ?? 70 13 07 20 06 ?? ?? 00 38 05 ?? ?? 00 00 07 6f 10 ?? ?? 0a 0c 20 03 ?? ?? 00 38 f3 ?? ?? 00 08 6f 11 ?? ?? 0a 28 12 ?? ?? 0a 73 13 ?? ?? 0a 0d 20 08 ?? ?? 00 38 d8 ?? ?? 00 00 72 35 ?? ?? 70 0a 20 09 ?? ?? 00 38 c7 ?? 00 00}  //weight: 6, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "GetResponseStream" ascii //weight: 1
        $x_1_5 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABM_2147824756_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABM!MTB"
        threat_id = "2147824756"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 06 8e 69 1d 2d 09 26 2b 12 0a 2b eb 0b 2b f1 0c 2b f5 2a 00 02 72 57 ?? ?? 70 28 0b ?? ?? 06 1a 2d 13 26 73 34 ?? ?? 0a 1b 2d 0d}  //weight: 2, accuracy: Low
        $x_1_2 = "set_SecurityProtocol" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABM_2147824756_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABM!MTB"
        threat_id = "2147824756"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 06 6f 18 ?? ?? 0a 0d 07 09 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 02 13 04 07 6f ?? ?? ?? 0a 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 dd ?? ?? ?? 00 08 39 ?? ?? ?? 00 08 6f ?? ?? ?? 0a dc}  //weight: 5, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABM_2147824756_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABM!MTB"
        threat_id = "2147824756"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {a2 09 17 7e ?? ?? ?? 0a a2 09 18 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a a2 09 13 04 08}  //weight: 3, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "GZipStream" ascii //weight: 1
        $x_1_5 = "CAccPropServicesClass.IAccPropServer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABG_2147824760_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABG!MTB"
        threat_id = "2147824760"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 03 0c 2b 00 07 16 73 03 ?? ?? 0a 73 04 ?? ?? 0a 0d 09 08 6f 05 ?? ?? 0a de 07 09 6f 06 ?? ?? 0a dc 08 6f 07 ?? ?? 0a 13 04 de 0e 55 00 72 01 ?? ?? 70 28 02 ?? ?? 06 18 2d 0d 26 06 73 01 ?? ?? 0a 18 2d 06 26 2b 06 0a 2b f1 0b 2b 00 73 02 ?? ?? 0a 1b 2d 03 26}  //weight: 5, accuracy: Low
        $x_1_2 = "WebClient" ascii //weight: 1
        $x_1_3 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABO_2147824764_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABO!MTB"
        threat_id = "2147824764"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 2c 07 09 6f 1a ?? ?? 0a 00 dc 08 6f 1b ?? ?? 0a 13 04 de 16 49 00 00 72 01 ?? ?? 70 28 04 ?? ?? 06 0a 06 73 15 ?? ?? 0a 0b 00 73 16 ?? ?? 0a 0c 00 07 16 73 17 ?? ?? 0a 73 18 ?? ?? 0a 0d 00 09 08 6f 19 ?? ?? 0a 00 00 de 0b}  //weight: 5, accuracy: Low
        $x_1_2 = "BufferedStream" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "WebClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABO_2147824764_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABO!MTB"
        threat_id = "2147824764"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0d 09 2c 68 00 06 72 ?? ?? ?? 70 08 72 74 ?? ?? 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 72 a0 ?? ?? 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 00 08 72 74 ?? ?? 70 28 ?? ?? ?? 0a 08 28 ?? ?? ?? 0a 00 1f 0a}  //weight: 4, accuracy: Low
        $x_1_2 = "ZipFile" ascii //weight: 1
        $x_1_3 = "GetFolderPath" ascii //weight: 1
        $x_1_4 = "ExtractToDirectory" ascii //weight: 1
        $x_1_5 = "RobloxPlayerBeta.zip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_EXV_2147826162_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.EXV!MTB"
        threat_id = "2147826162"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "20.238.37.241/Update/" wide //weight: 1
        $x_1_2 = "IMuiResourceIdLookupMapEntry.dll" wide //weight: 1
        $x_1_3 = "SubcategoryMembershipEntryFieldId" wide //weight: 1
        $x_1_4 = "WindowClassEntryFieldId" wide //weight: 1
        $x_1_5 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 44 6f 77 6e 6c 6f 61 64 44 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 47 65 74 54 79 70 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_NYD_2147826833_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.NYD!MTB"
        threat_id = "2147826833"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 39 00 00 01 25 19 6f 49 00 00 0a 6f 4a 00 00 0a 74 14 00 00 01 0a 06 6f 4b 00 00 0a 0b 07 73 4c 00 00 0a 0c 08 6f 4d 00 00 0a 0d de 27}  //weight: 1, accuracy: High
        $x_1_2 = {3f a2 1d 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 51 00 00 00 18 00 00 00 23 00 00 00 54 00 00 00 3d 00 00 00 03 00 00 00 9a 00 00 00 07}  //weight: 1, accuracy: High
        $x_1_3 = "VideoPlayer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_MA_2147826873_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.MA!MTB"
        threat_id = "2147826873"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "://trigonevo.xyz/bruh/xd" wide //weight: 10
        $x_10_2 = "://trigonevo.com/files/xd" wide //weight: 10
        $x_1_3 = "DownloadString" ascii //weight: 1
        $x_1_4 = "PornDownload" ascii //weight: 1
        $x_1_5 = "Please disable antivirus" wide //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
        $x_1_7 = "taskkill /F /IM Trigon" wide //weight: 1
        $x_1_8 = "echo j | del autodelete.bat" wide //weight: 1
        $x_1_9 = "PornChecked" ascii //weight: 1
        $x_1_10 = "MemoryStream" ascii //weight: 1
        $x_1_11 = "./Trigon/bin/Trigon.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_BF_2147827178_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.BF!MTB"
        threat_id = "2147827178"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "107.172.13.154" wide //weight: 5
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_BF_2147827178_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.BF!MTB"
        threat_id = "2147827178"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aparatedecuratat.ro/MANNY/newDDLLLLL.txt" wide //weight: 1
        $x_1_2 = "UE8wNTMyMjAyMiU" wide //weight: 1
        $x_1_3 = "THEDEVIL.DEVILDEVIL" wide //weight: 1
        $x_1_4 = "CheckRemoteDebuggerPresent" wide //weight: 1
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABI_2147827394_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABI!MTB"
        threat_id = "2147827394"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 df a3 1d 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 bb 00 00 00 f2 00 00 00 f9 01 00 00 00 04 00 00 eb 02 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "HttpWebRequest" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "Debugger" ascii //weight: 1
        $x_1_5 = "GetFolderPath" ascii //weight: 1
        $x_1_6 = "get_IsAttached" ascii //weight: 1
        $x_1_7 = "IsLogging" ascii //weight: 1
        $x_1_8 = "GetAllNetworkInterfaces" ascii //weight: 1
        $x_1_9 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABI_2147827394_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABI!MTB"
        threat_id = "2147827394"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {13 06 11 06 28 26 ?? ?? 0a 13 07 28 27 ?? ?? 0a 11 07 6f 28 ?? ?? 0a 13 08 7e 29 ?? ?? 0a 26 08 28 26 ?? ?? 0a 13 09 28 27 ?? ?? 0a 11 09 6f 28 ?? ?? 0a 13 0a 07 28 26 ?? ?? 0a 13 0b 28 27 ?? ?? 0a 11 0b 6f 28 ?? ?? 0a 13 0c 73 24 ?? ?? 0a 11 0c 28 2a ?? ?? 0a 13 0d 06 11 0a 6f 2a ?? ?? 0a 13 0e 19 8d 01 ?? ?? 01 13 11 11 11 16}  //weight: 6, accuracy: Low
        $x_1_2 = "GetEnumerator" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABD_2147827751_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABD!MTB"
        threat_id = "2147827751"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 0a 02 06 28 ?? ?? ?? 06 0b 07 2a 16 00 02 72 ?? ?? ?? 70 28 04}  //weight: 4, accuracy: Low
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "WebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_D_2147828364_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.D!MTB"
        threat_id = "2147828364"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 0c 00 00 28 ?? ?? ?? 0a ?? 28 ?? ?? ?? 06 0a 06 6f ?? ?? ?? 0a 74 ?? ?? ?? 01 0b 2b 00 07 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {72 01 00 00 70 73 ?? ?? ?? 0a 28 ?? ?? ?? 0a 74 ?? ?? ?? 01 0a 2b 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_3 = {0a 00 06 6f ?? ?? ?? 0a 80 ?? ?? ?? 04 00 de 21 00 0a 00 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 06 6f}  //weight: 1, accuracy: Low
        $x_1_4 = {59 d2 9c 00 06 17 58 0a 06 7e ?? ?? ?? 04 8e 69 fe ?? 0b 07 2d 28 00 7e ?? ?? ?? 04 06 7e ?? ?? ?? 04 06 91 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABQ_2147828473_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABQ!MTB"
        threat_id = "2147828473"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 05 16 11 04 6f ?? ?? ?? 0a 08 11 05 16 11 05 8e 69 6f ?? ?? ?? 0a 25 13 04 16 30 e2 09 6f ?? ?? ?? 0a 0a de 1e}  //weight: 5, accuracy: Low
        $x_5_2 = {0a 19 6f 17 ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 d0 ?? ?? ?? 02 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 17 8d ?? ?? ?? 01 25 16 02 a2 6f ?? ?? ?? 06 de 03 3f 00 72 31 ?? ?? 70 28 16}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABQ_2147828473_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABQ!MTB"
        threat_id = "2147828473"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 df a3 1d 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 b7 00 00 00 f0 00 00 00 f9 01 00 00 fd 03 00 00 eb 02 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "WebRequest" ascii //weight: 1
        $x_1_3 = "HttpWebResponse" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "GetFolderPath" ascii //weight: 1
        $x_1_6 = "get_IsAttached" ascii //weight: 1
        $x_1_7 = "IsLogging" ascii //weight: 1
        $x_1_8 = "GetAllNetworkInterfaces" ascii //weight: 1
        $x_1_9 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABZ_2147828600_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABZ!MTB"
        threat_id = "2147828600"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 1a 2d 15 2b 0d 06 16 06 8e 69 1c 2d 0e 26 26 26 2b 03 26 2b f0 06 2b 0a 0a 2b ea 28 ?? ?? ?? 0a 2b f3 2a 2d 00 72 01 ?? ?? 70 28 02}  //weight: 5, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABL_2147828761_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABL!MTB"
        threat_id = "2147828761"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {06 0a 2b 07 28 ?? ?? ?? 06 2b eb 06 16 06 8e 69 28 ?? ?? ?? 0a 2b 07 21 00 02 72 ?? ?? ?? 70 28 06}  //weight: 8, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABL_2147828761_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABL!MTB"
        threat_id = "2147828761"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 06 6f 2a ?? ?? 0a 0d 07 09 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 02 13 04 07 6f ?? ?? ?? 0a 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 dd ?? ?? ?? 00 08 39 ?? ?? ?? 00 08 6f ?? ?? ?? 0a dc}  //weight: 5, accuracy: Low
        $x_5_2 = {07 09 16 11 04 6f ?? ?? ?? 0a 08 09 16 09 8e 69 6f ?? ?? ?? 0a 25 13 04 16 3d ?? ?? ?? ff 07 6f ?? ?? ?? 0a 13 05}  //weight: 5, accuracy: Low
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_BA_2147828795_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.BA!MTB"
        threat_id = "2147828795"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b 3d 2b 42 2b 43 2b 48 16 16 2c 47 26 2b 17 2b 45 07 09 07 8e 69 5d 91 06 09 91 61 d2 6f}  //weight: 2, accuracy: High
        $x_1_2 = "23.95.106.35" wide //weight: 1
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_BB_2147828796_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.BB!MTB"
        threat_id = "2147828796"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 09 8e 69 13 04 2b 0a 06 09 11 04 91 6f ?? ?? ?? 0a 11 04 25 17 59 13 04 16 fe 02 2d ea}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_BC_2147828818_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.BC!MTB"
        threat_id = "2147828818"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 11 04 08 11 04 08 8e 69 5d 91 06 11 04 91 61 d2}  //weight: 2, accuracy: High
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_F_2147829378_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.F!MTB"
        threat_id = "2147829378"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 11 06 a2 25 1f 14 28 ?? 00 00 2b 1f 18 28 ?? 00 00 2b 8c ?? 00 00 01 a2 13 16 00 a2 25 1f ?? 28 ?? 00 00 2b 7e ?? 00 00 0a a2 25 1f 10 28}  //weight: 2, accuracy: Low
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "ReadToEnd" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABT_2147829607_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABT!MTB"
        threat_id = "2147829607"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 0a 06 2a 12 00 72 59 ?? ?? 70 28 10 ?? ?? 06 28 12}  //weight: 5, accuracy: Low
        $x_5_2 = {07 08 16 11 05 6f ?? ?? ?? 0a 06 08 16 08 8e 69 6f ?? ?? ?? 0a 25 13 05 16 fe 03 2d e3 07 6f ?? ?? ?? 0a 13 06 de 0a}  //weight: 5, accuracy: Low
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_NXD_2147829820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.NXD!MTB"
        threat_id = "2147829820"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 95 02 20 09 02 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 2b 00 00 00 04 00 00 00 01 00 00 00 04 00 00 00 01 00 00 00 25 00 00 00 0e 00 00 00 01 00 00 00 03 00 00 00 01 00 00 00 01 00 00 00 02 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = "DynamicInvoke" ascii //weight: 1
        $x_1_3 = "GetDomain" ascii //weight: 1
        $x_1_4 = "CreateDelegate" ascii //weight: 1
        $x_1_5 = "TripleDESCryptoServiceProvider" ascii //weight: 1
        $x_1_6 = "ComputeHash" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABR_2147831435_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABR!MTB"
        threat_id = "2147831435"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "set_Password" ascii //weight: 1
        $x_1_2 = "ZipFile" ascii //weight: 1
        $x_1_3 = "GetTempPath" ascii //weight: 1
        $x_1_4 = "w3)Jhb2iU4<NLs_P" wide //weight: 1
        $x_1_5 = "WWpOQ01HRlhPWFZqTXpFd1pVaFJQUT09" wide //weight: 1
        $x_1_6 = "$fedbe1d0-c630-4e55-9539-9a7f0fa7f788" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABN_2147832233_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABN!MTB"
        threat_id = "2147832233"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String" ascii //weight: 1
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "Select* from tblNhaCungCap where maNCC= @maNCC" wide //weight: 1
        $x_1_4 = "1(PE)366(PE)361(PE)358(PE)362(PE)362" wide //weight: 1
        $x_1_5 = "Mzc5IDM3NyA0MTEgNDExIDM5MiA0MjYgNDIzID" wide //weight: 1
        $x_1_6 = "QyNCAzOTUgNDEzIDQyNiA0MzAgNDE3IDQxMSA0" wide //weight: 1
        $x_1_7 = "4NSAzOD" wide //weight: 1
        $x_1_8 = "zk2IDQz" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_AMCN_2147832524_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.AMCN!MTB"
        threat_id = "2147832524"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 13 00 00 04 1a 9a 7e 14 00 00 04 7e 15 00 00 04 28}  //weight: 2, accuracy: High
        $x_1_2 = "VjJ0ak5XUkdiRmhpU0ZacVpXNW5kMXBWYUZKUVVUMDk=" wide //weight: 1
        $x_1_3 = "V1hwT1YyRldRa2xWYWxKclVWUXdPUT09" wide //weight: 1
        $x_1_4 = "V1ZSS1YwNVdRa2xWYWxKclVWUXdPUT09" wide //weight: 1
        $x_1_5 = "VjFab1MyRnRSa1ZsUkZwb1YwVkZPUT09" wide //weight: 1
        $x_1_6 = "V1dwT1EwMUhSbGhQV0ZacVpXNW5kMXBWYUZKUVVUMDk=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_AW_2147832733_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.AW!MTB"
        threat_id = "2147832733"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8e 69 5d 91 2b 44 2b 45 91 61 d2 6f ?? ?? ?? 0a 07 1d 2c 04 17 58 0b 07 02 8e 69 32 db}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_BJ_2147832734_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.BJ!MTB"
        threat_id = "2147832734"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "185.232.166.10/assets" wide //weight: 2
        $x_2_2 = "Yozrfutnj" wide //weight: 2
        $x_2_3 = "$cab8d1bc-9b37-4640-87a4-0e30df297919" ascii //weight: 2
        $x_1_4 = "ReadBytes" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABK_2147832739_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABK!MTB"
        threat_id = "2147832739"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {1e 5b 6f 3b ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 6f ?? ?? ?? 0a 00 08 09 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 06 00 11 06 02 16 02 8e 69 6f ?? ?? ?? 0a 00 11 06 6f ?? ?? ?? 0a 00 00 de 0d 11 06 2c 08 11 06 6f ?? ?? ?? 0a 00 dc 08 6f ?? ?? ?? 0a 0a 00 de 0b}  //weight: 4, accuracy: Low
        $x_1_2 = "afasfsafsafsafsafasAFSAF" wide //weight: 1
        $x_1_3 = "safsas.safsas" wide //weight: 1
        $x_1_4 = "safsa" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABAE_2147833108_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABAE!MTB"
        threat_id = "2147833108"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 11 05 11 33 94 b4 6f ?? ?? ?? 0a 00 11 33 17 d6 13 33 11 33 11 32 31 e6 11 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 07 16 13 08 11 07}  //weight: 1, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "SGBITPlacementManagementSystem.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABAO_2147833560_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABAO!MTB"
        threat_id = "2147833560"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 08 18 5b 02 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 08 18 58 0c 08 06 32 e4 07 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "WindowsFormsApp96.Forms.Form1.resources" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABAX_2147833564_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABAX!MTB"
        threat_id = "2147833564"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 11 04 2b 09 06 18 6f ?? ?? ?? 0a 2b 07 6f ?? ?? ?? 0a 2b f0 02 0c 2b 04 13 04 2b e3 06 6f ?? ?? ?? 0a 08 16 08 8e 69 6f ?? ?? ?? 0a 13 05 de 0e}  //weight: 1, accuracy: Low
        $x_1_2 = "TransformFinalBlock" ascii //weight: 1
        $x_1_3 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABBD_2147834308_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABBD!MTB"
        threat_id = "2147834308"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0d 07 09 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 02 13 04 07 6f ?? ?? ?? 0a 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 dd ?? ?? ?? 00 08 39 ?? ?? ?? 00 08 6f ?? ?? ?? 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABBR_2147834852_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABBR!MTB"
        threat_id = "2147834852"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InvokeMember" ascii //weight: 1
        $x_1_2 = "$94c3a87d-845b-49f6-aa4f-007513333549" ascii //weight: 1
        $x_1_3 = "baskanprojesi.Properties.Resources" wide //weight: 1
        $x_1_4 = "manita.nerdesin" wide //weight: 1
        $x_1_5 = "combobox" wide //weight: 1
        $x_1_6 = "yarkaprojesi" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_K_2147835159_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.K!MTB"
        threat_id = "2147835159"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 25 26 25 16 20 ?? 00 00 00 28 ?? 00 00 06 [0-2] a2 25 17 7e ?? 00 00 0a a2 25 18 11 06 a2 25 19 17 8c ?? 00 00 01 a2 13 08 11}  //weight: 2, accuracy: Low
        $x_1_2 = "GetType" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABDQ_2147835894_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABDQ!MTB"
        threat_id = "2147835894"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {26 06 08 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 0d 06 6f ?? ?? ?? 0a 09 16 09 8e 69 6f ?? ?? ?? 0a 13 04 de 11 0c 2b d5 07 6f ?? ?? ?? 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "TransformFinalBlock" ascii //weight: 1
        $x_1_3 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_NZS_2147836667_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.NZS!MTB"
        threat_id = "2147836667"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 73 00 6f 00 6f 00 31 00 34 00 35 00 31 00 2e 00 64 00 64 00 6e 00 73 00 2e 00 6e 00 65 00 74 00 3a 00 31 00 34 00 35 00 33 00 2f 00 [0-24] 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {73 73 6f 6f 31 34 35 31 2e 64 64 6e 73 2e 6e 65 74 3a 31 34 35 33 2f [0-24] 2e 70 6e 67}  //weight: 1, accuracy: Low
        $x_1_3 = "u6nHGiwhHY2jMCJmgs.FtMkWlnaFargBND7mv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_MP_2147836846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.MP!MTB"
        threat_id = "2147836846"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 13 05 11 09 09 94 13 07 11 09 09 11 09 11 05 94 9e 11 09 11 05 11 07 9e 11 09 11 09 09 94 11 09 11 05 94 58}  //weight: 1, accuracy: High
        $x_1_2 = {5d 94 13 06 08 11 04 07 11 04 91 11 06 61 d2 9c 11 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_MPA_2147836847_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.MPA!MTB"
        threat_id = "2147836847"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1e 2c 0d 17 2c 0a 1d 2c 07 2c 04 1e 2c ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABS_2147837014_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABS!MTB"
        threat_id = "2147837014"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 14 02 00 09 00 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 10 00 00 00 03 00 00 00 03 00 00 00 04 00 00 00 16 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "GetCommandLineArgs" ascii //weight: 1
        $x_1_3 = "simpledownloader" ascii //weight: 1
        $x_1_4 = "Downloading" wide //weight: 1
        $x_1_5 = "Check if the internet address is valid" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABFV_2147837422_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABFV!MTB"
        threat_id = "2147837422"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 31 2b 61 2b 62 72 ?? ?? ?? 70 2b 65 2b 6d 38 ?? ?? ?? 00 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 8e 69 5d 91 06 08 91 61 d2 6f ?? ?? ?? 0a 08 16 2d 04 17 58 0c 08 06 8e}  //weight: 2, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "GetResponseStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ANLL_2147837446_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ANLL!MTB"
        threat_id = "2147837446"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 11 06 9a 17 8d 27 00 00 01 25 16 1f 3a 9d 6f ?? ?? ?? 0a 13 07 11 07 16 9a 11 07 17 9a 28}  //weight: 2, accuracy: Low
        $x_1_2 = "Mega.NZ Checker Started" wide //weight: 1
        $x_1_3 = "Checking Done!" wide //weight: 1
        $x_1_4 = "hits in hit.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_MPB_2147837746_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.MPB!MTB"
        threat_id = "2147837746"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 11 04 08 11 04 08 8e 69 5d 91 06 11 04 91 61 d2 9c 11 04 17 58 13 04 11 04 06 8e 69 32 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_RDJ_2147837813_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.RDJ!MTB"
        threat_id = "2147837813"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 11 05 09 11 05 09 8e 69 5d 91 08 11 05 91 61 d2 6f ?? ?? ?? ?? 11 05 17 58 13 05 11 05 08 8e 69}  //weight: 2, accuracy: Low
        $x_1_2 = "d5274f60-3387-4398-a363-5e59d4524fa0" ascii //weight: 1
        $x_1_3 = "Eimuyrs.Kvfgdjlevgujjdvhneuh" wide //weight: 1
        $x_1_4 = "Afvkglrxbmcqtsrghdqubmgx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_M_2147837854_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.M!MTB"
        threat_id = "2147837854"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "150 G150 e150 t150 T150 y150 p150 e150" wide //weight: 2
        $x_2_2 = "150 L150 o150 a150 d" wide //weight: 2
        $x_2_3 = "150 E150 nt150 ry150 Po150 in150 t" wide //weight: 2
        $x_2_4 = "150 In150 vo150 k150 e" wide //weight: 2
        $x_2_5 = "CRAZY_SEAL" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABFG_2147837953_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABFG!MTB"
        threat_id = "2147837953"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 0d 2b 0f 18 2b 10 1f 10 2b 10 2b 12 de 35 2b 11 2b ef 2b 10 2b ed 2b 0f 2b ec 2b 12 2b ec 0a 2b eb 02 2b ec 03 2b ed 6f ?? ?? ?? 0a 2b ea 28 ?? ?? ?? 0a 2b e7}  //weight: 2, accuracy: Low
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABKO_2147839357_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABKO!MTB"
        threat_id = "2147839357"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 13 01 38 ?? ?? ?? 00 dd ?? ?? ?? 00 26 30 00 28 ?? ?? ?? 06 72 ?? ?? ?? 70 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 2b 28}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_CTT_2147841048_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.CTT!MTB"
        threat_id = "2147841048"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "https://kedaiorangmelayu.xyz/loader/uploads/withoutstartup_Kkxjpjme.bmp" ascii //weight: 10
        $x_1_2 = "AwakeServer" ascii //weight: 1
        $x_1_3 = "CallServer" ascii //weight: 1
        $x_1_4 = "InstantiateServer" ascii //weight: 1
        $x_1_5 = "withoutstartup.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_CTS_2147841049_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.CTS!MTB"
        threat_id = "2147841049"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-31] 2e 00 [0-5] 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 77 00 69 00 74 00 68 00 6f 00 75 00 74 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 5f 00 [0-32] 2e 00 62 00 6d 00 70 00}  //weight: 10, accuracy: Low
        $x_10_2 = {68 74 74 70 73 3a 2f 2f [0-31] 2e [0-5] 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f 77 69 74 68 6f 75 74 73 74 61 72 74 75 70 5f [0-32] 2e 62 6d 70}  //weight: 10, accuracy: Low
        $x_1_3 = "withoutstartup.exe" ascii //weight: 1
        $x_1_4 = "Make Computer faster and more secure" ascii //weight: 1
        $x_1_5 = "KDE Softwares" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_CTJ_2147841050_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.CTJ!MTB"
        threat_id = "2147841050"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-31] 2e 00 [0-5] 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 77 00 69 00 74 00 68 00 6f 00 75 00 74 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 5f 00 [0-32] 2e 00 6a 00 70 00 67 00}  //weight: 10, accuracy: Low
        $x_10_2 = {68 74 74 70 73 3a 2f 2f [0-31] 2e [0-5] 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f 77 69 74 68 6f 75 74 73 74 61 72 74 75 70 5f [0-32] 2e 6a 70 67}  //weight: 10, accuracy: Low
        $x_1_3 = "withoutstartup.exe" ascii //weight: 1
        $x_1_4 = "Make Computer faster and more secure" ascii //weight: 1
        $x_1_5 = "KDE Softwares" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_AgentTesla_CAG_2147841199_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.CAG!MTB"
        threat_id = "2147841199"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0a 2b 66 00 72 ?? 00 00 70 28 ?? 00 00 06 73 ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 07 16 73 ?? 00 00 0a 73 ?? 00 00 0a 0d 09 08 6f ?? 00 00 0a de 0a}  //weight: 2, accuracy: Low
        $x_2_2 = {07 2c 06 07 6f ?? 00 00 0a dc 26 20 e0 2e 00 00 28 ?? 00 00 0a de}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_CAH_2147841590_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.CAH!MTB"
        threat_id = "2147841590"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 01 00 00 70 28 ?? 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 72 ?? 00 00 70 7e ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 0b de 03 26 de cf 07 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "GetType" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ATA_2147842156_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ATA!MTB"
        threat_id = "2147842156"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 16 0b 2b 19 06 03 07 18 6f 08 00 00 0a 1f 10 28 09 00 00 0a 6f 0a 00 00 0a 07 18 58 0b 07 03 6f 0b 00 00 0a 32 de}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABOI_2147842972_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABOI!MTB"
        threat_id = "2147842972"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 8e 69 5d 91 02 07 91 61 d2 6f ?? ?? ?? 0a 07 17 58 0b 07 02 8e 69 32 dc 06 6f ?? ?? ?? 0a 25 2d 02 26 14 2a 30 00 06 7e ?? ?? ?? 04 07 7e}  //weight: 5, accuracy: Low
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "GetTypes" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_KAC_2147844632_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.KAC!MTB"
        threat_id = "2147844632"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 49 00 00 70 28 ?? 00 00 06 0d 09 8e 69 13 04 2b 0a 06 09 11 04 91 6f ?? 00 00 0a 11 04 25 17 59 13 04 16 fe 02 2d ea 06 6f}  //weight: 1, accuracy: Low
        $x_1_2 = "://cdn.discordapp.com/attachments/" wide //weight: 1
        $x_1_3 = "get_Now" ascii //weight: 1
        $x_1_4 = "AddSeconds" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_MBEF_2147849063_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.MBEF!MTB"
        threat_id = "2147849063"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 00 37 00 32 00 2e 00 32 00 34 00 35 00 2e 00 31 00 39 00 31 00 2e 00 31 00 37 00 2f 00 30 00 30 00 30 00 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_Q_2147850695_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.Q!MTB"
        threat_id = "2147850695"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 09 11 05 18 6f ?? 00 00 0a 1f 10 28}  //weight: 2, accuracy: Low
        $x_2_2 = {11 05 18 58 13 05 11 05 09 6f}  //weight: 2, accuracy: High
        $x_1_3 = "ReadAsByteArrayAsync" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_AMAA_2147853393_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.AMAA!MTB"
        threat_id = "2147853393"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 20 97 59 c0 e0 28 ?? 01 00 06 28 ?? 01 00 0a 6f ?? 01 00 0a 06 20 ?? ?? ?? e0 28 ?? 01 00 06 28 ?? 01 00 0a 6f ?? 01 00 0a 06 06 6f ?? 01 00 0a 06 6f ?? 01 00 0a 6f ?? 01 00 0a 13 05 73 ?? 00 00 0a 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_R_2147890061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.R!MTB"
        threat_id = "2147890061"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Powershell" wide //weight: 2
        $x_2_2 = "VBscript" wide //weight: 2
        $x_2_3 = "CreateObject(\"Shell.Application\")" ascii //weight: 2
        $x_2_4 = "Runme" ascii //weight: 2
        $x_1_5 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ATL_2147896119_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ATL!MTB"
        threat_id = "2147896119"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 06 18 5b 8d 32 00 00 01 0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f 43 00 00 0a 1f 10 28 44 00 00 0a 9c 08 18 58 0c 08 06 32 e4}  //weight: 2, accuracy: High
        $x_1_2 = "transfer.sh" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ALA_2147896120_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ALA!MTB"
        threat_id = "2147896120"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 06 18 5b 8d 2b 00 00 01 0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f 33 00 00 0a 1f 10 28 34 00 00 0a 9c 08 18 58 0c 08 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_KAA_2147896228_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.KAA!MTB"
        threat_id = "2147896228"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 08 13 06 16 13 07 11 06 12 07 28 ?? 00 00 0a 00 08 07 11 05 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 de 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABKF_2147896477_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABKF!MTB"
        threat_id = "2147896477"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 13 01 38 ?? ?? ?? 00 dd ?? ?? ?? 00 26 30 00 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 2b 28}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABFA_2147896493_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABFA!MTB"
        threat_id = "2147896493"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 2b 19 16 2d f4 1e 2c e2 2b 18 2a 28 ?? ?? ?? 06 2b e5 0a 2b e4 06 2b e3 06 2b e3 28 ?? ?? ?? 0a 2b e0 06 2b e5}  //weight: 1, accuracy: Low
        $x_1_2 = "Wivvtkfqczyqkzlps.Wefinuuarvykvu" wide //weight: 1
        $x_1_3 = "Vtiijrimqrvbljaiaci" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_ABBG_2147896521_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.ABBG!MTB"
        threat_id = "2147896521"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 0c 16 0d 08 12 03 28 ?? ?? ?? 0a 06 02 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a de 0a 09 2c 06 08 28 ?? ?? ?? 0a dc 07 18 58 0b 07 02 6f ?? ?? ?? 0a 32 c6 06 6f ?? ?? ?? 0a 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_AS_2147896626_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.AS!MTB"
        threat_id = "2147896626"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2c 21 69 16 2d 17 2b 60 2b 0e 00 2b 5e 2b 5f 08 91 6f 29 ?? ?? 0a 00 00 08 25 17 59 0c 16 25 2d fb fe 02 36 00 72 71 ?? ?? 70 2b 5e 38 63 ?? ?? 00 38 64 ?? ?? 00 8e 1d}  //weight: 2, accuracy: Low
        $x_2_2 = {13 04 2b 00 19 2c cf 11 04 2a 12 00 06 6f 2a ?? ?? 0a 0b 07}  //weight: 2, accuracy: Low
        $x_1_3 = "WebClient" ascii //weight: 1
        $x_1_4 = "DateTime" ascii //weight: 1
        $x_1_5 = "op_GreaterThan" ascii //weight: 1
        $x_1_6 = "get_Assembly" ascii //weight: 1
        $x_1_7 = "DownloadData" ascii //weight: 1
        $x_1_8 = "DynamicInvoke" ascii //weight: 1
        $x_1_9 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_DIG_2147942740_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.DIG!MTB"
        threat_id = "2147942740"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "evXCrwb/ca0kO5SN3lwjbw==" ascii //weight: 1
        $x_1_2 = "XPTcA7LGf5R6Jbesh8.jIuNk0l1PwYyv2bEFd" ascii //weight: 1
        $x_1_3 = "(Macintosh; Intel Mac OS X 13_3_1)" ascii //weight: 1
        $x_2_4 = "https://files.catbox.moe/jty6a2.wav" ascii //weight: 2
        $x_1_5 = "Leswvbebd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AgentTesla_PMZ_2147947038_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AgentTesla.PMZ!MTB"
        threat_id = "2147947038"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 3a 1a 00 00 00 73 04 00 00 0a 72 01 00 00 70 73 05 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 0a 06 39 0a 00 00 00 06 16 06 8e 69 28 ?? 00 00 0a dd 13 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

