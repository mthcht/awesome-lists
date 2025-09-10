rule Trojan_MSIL_LokiBot_DA_2147778921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.DA!MTB"
        threat_id = "2147778921"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 9a 28 ?? ?? ?? 0a 0d 7e ?? ?? ?? 04 09 6f ?? ?? ?? 0a 00 00 08 17 d6 0c 08 07 8e 69 fe 04 13 04 11 04 2d da}  //weight: 1, accuracy: Low
        $x_1_2 = "Shop_Manager" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_DA_2147778921_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.DA!MTB"
        threat_id = "2147778921"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$5d3f6da4-bfb8-401a-9ee8-bf4d3fda0b24" ascii //weight: 20
        $x_20_2 = "$aec3172a-0820-4b87-bf61-88aaed374c36" ascii //weight: 20
        $x_1_3 = "SchoolBookManager.Resources.resources" ascii //weight: 1
        $x_1_4 = "WinMain.My.Resources" ascii //weight: 1
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_9 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "DebuggingModes" ascii //weight: 1
        $x_1_12 = "CreateInstance" ascii //weight: 1
        $x_1_13 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_LokiBot_DB_2147780440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.DB!MTB"
        threat_id = "2147780440"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0b 16 0c 2b 14 07 06 08 9a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 08 17 58 0c 08 20 00 38 01 00 32 e4}  //weight: 3, accuracy: Low
        $x_1_2 = "Magna.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "Split" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_DB_2147780440_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.DB!MTB"
        threat_id = "2147780440"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Shop_Manager.My.Resources" ascii //weight: 10
        $x_10_2 = "Shops_DBDataSet" ascii //weight: 10
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "Activator" ascii //weight: 1
        $x_1_5 = "Debugger" ascii //weight: 1
        $x_1_6 = "ToString" ascii //weight: 1
        $x_1_7 = "Convert" ascii //weight: 1
        $x_1_8 = "Concat" ascii //weight: 1
        $x_1_9 = "Split" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_LokiBot_DB_2147780440_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.DB!MTB"
        threat_id = "2147780440"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$0cb05e7b-7e51-4ef0-a0ec-8c59e0b25c16" ascii //weight: 20
        $x_20_2 = "ValheimServerManager.My.Resources" ascii //weight: 20
        $x_1_3 = "ValheimServerManager.Resources" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_5 = "Manages a Valheim Game Server" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_LokiBot_AQE_2147781246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.AQE!MTB"
        threat_id = "2147781246"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 9a 14 19 8d ?? ?? ?? 01 25 16 28 ?? ?? ?? 06 a2 25 17 28 ?? ?? ?? 06 a2 25 18 ?? ?? ?? ?? ?? 28 ?? ?? ?? 06 a2 14 6f ?? ?? ?? 0a 20 00 08 00 00 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "GetType" ascii //weight: 1
        $x_1_3 = "GetMethod" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
        $x_1_6 = "ToInt32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_LokiBot_HDF_2147781886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.HDF!MTB"
        threat_id = "2147781886"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XOR_Decrypt" ascii //weight: 1
        $x_1_2 = "sadada" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "My.Computer" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "Dispose__Instance" ascii //weight: 1
        $x_1_7 = "ToString" ascii //weight: 1
        $x_1_8 = "GetType" ascii //weight: 1
        $x_1_9 = "LateGet" ascii //weight: 1
        $x_1_10 = "ThreadAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_DEN_2147811058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.DEN!MTB"
        threat_id = "2147811058"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "get_ControlDarkDark" ascii //weight: 3
        $x_3_2 = "HrmpProgram" ascii //weight: 3
        $x_3_3 = "HrmpInterpreter.Commands" ascii //weight: 3
        $x_3_4 = "HrmpInterpreter.Journals" ascii //weight: 3
        $x_3_5 = "RazerInstaller" ascii //weight: 3
        $x_3_6 = "DebuggingModes" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CM_2147813926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CM!MTB"
        threat_id = "2147813926"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "globalGameState" ascii //weight: 3
        $x_3_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 3
        $x_3_3 = "get_RSAPKCS1SHA384" ascii //weight: 3
        $x_3_4 = "GhostParty.Properties.Resources" ascii //weight: 3
        $x_3_5 = "Galaxy Man" ascii //weight: 3
        $x_3_6 = "MoveGuestDownHallway" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_ER_2147816389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.ER!MTB"
        threat_id = "2147816389"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".edom SOD ni nur eb tonnac margorp sihT!" ascii //weight: 1
        $x_1_2 = "lld.eerocsm" ascii //weight: 1
        $x_1_3 = "niaMllDroC_" ascii //weight: 1
        $x_1_4 = "HttpWebRequest" ascii //weight: 1
        $x_1_5 = "MemoryStream" ascii //weight: 1
        $x_1_6 = "Mozilla" ascii //weight: 1
        $x_1_7 = "Sleep" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_EQ_2147816484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.EQ!MTB"
        threat_id = "2147816484"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 17 a2 09 09 0b 00 00 00 5a a4 01 00 16 00 00 01 00 00 00 59 00 00 00 15 00 00 00 30 00 00 00 5c 00 00 00 6d 00 00 00 02}  //weight: 10, accuracy: High
        $x_10_2 = {57 17 a2 09 09 0b 00 00 00 5a a4 01 00 16 00 00 01 00 00 00 57 00 00 00 15 00 00 00 30 00 00 00 5d 00 00 00 6d 00 00 00 02}  //weight: 10, accuracy: High
        $x_1_3 = "HttpWebRequest" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "get_CurrentDomain" ascii //weight: 1
        $x_1_6 = "Another" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_LokiBot_ES_2147817059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.ES!MTB"
        threat_id = "2147817059"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$d27cb7bd-3c94-44e6-adf3-8cee15a64a2c" ascii //weight: 1
        $x_1_2 = "CompressionMode" ascii //weight: 1
        $x_1_3 = "GZipStream" ascii //weight: 1
        $x_1_4 = "Star Interior Design" ascii //weight: 1
        $x_1_5 = "BinaryFileSchema" ascii //weight: 1
        $x_1_6 = "get_Y" ascii //weight: 1
        $x_1_7 = "get_X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_ET_2147817291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.ET!MTB"
        threat_id = "2147817291"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 00 2e 00 37 00 30 00 2e 00 32 00 34 00 37 00 2e 00 32 00 32 00 39 00 2f 00 63 00 6c 00 61 00 73 00 73 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 [0-80] 2e 00 70 00 6e 00 67 00}  //weight: 10, accuracy: Low
        $x_10_2 = {33 00 2e 00 37 00 30 00 2e 00 32 00 34 00 37 00 2e 00 32 00 32 00 39 00 2f 00 63 00 6c 00 61 00 73 00 73 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 [0-80] 2e 00 6a 00 70 00 67 00}  //weight: 10, accuracy: Low
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
        $x_1_6 = "WebResponse" ascii //weight: 1
        $x_1_7 = "CopyTo" ascii //weight: 1
        $x_1_8 = "Sleep" ascii //weight: 1
        $x_1_9 = "System.Threading" ascii //weight: 1
        $x_1_10 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_LokiBot_NTX_2147818434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.NTX!MTB"
        threat_id = "2147818434"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FDSSSSSSSSSSSSW" ascii //weight: 1
        $x_1_2 = "WDCWCFDRR" ascii //weight: 1
        $x_1_3 = "UBYHNYGVTBFVTR" ascii //weight: 1
        $x_1_4 = {00 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 00}  //weight: 1, accuracy: High
        $x_1_5 = "GetTypes" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_NUX_2147819474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.NUX!MTB"
        threat_id = "2147819474"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 5f a2 c9 09 0b 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 88 00 00 00 19 00 00 00 56 00 00 00 c4 01 00 00 ab 00 00 00 03 00 00 00 e9 00 00 00 02 00 00 00 95}  //weight: 1, accuracy: High
        $x_1_2 = "$9e7190c2-1f5e-4afa-ba09-8ac996ea6d7b" ascii //weight: 1
        $x_1_3 = "TypingGame.Form1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_FA_2147819726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.FA!MTB"
        threat_id = "2147819726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".edom SOD ni nur eb tonnac margorp sihT!" ascii //weight: 1
        $x_1_2 = "HttpWebRequest" ascii //weight: 1
        $x_1_3 = "GetTypes" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "Xrdehdnwonodqhavci" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_FB_2147819989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.FB!MTB"
        threat_id = "2147819989"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 16 18 01 00 0c 2b 13 00 07 08 20 00 01 00 00 28 ?? ?? ?? 06 0b 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e2}  //weight: 1, accuracy: Low
        $x_1_2 = "GetMethod" ascii //weight: 1
        $x_1_3 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_FC_2147819990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.FC!MTB"
        threat_id = "2147819990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 03 17 58 7e ?? ?? ?? 04 5d 91 0a 16 0b 17 0c 00 02 03 28 ?? ?? ?? 06 0d 06 04 58 13 04 09 11 04 59 04 5d 0b 00 02 03 7e ?? ?? ?? 04 5d 07 d2 9c 02 13 05 2b 00 11 05 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "GetMethod" ascii //weight: 1
        $x_1_3 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPC_2147820123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPC!MTB"
        threat_id = "2147820123"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 16 08 02 00 0c 2b 13 00 06 08 20 00 01 00 00 28 07 00 00 06 0a 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPC_2147820123_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPC!MTB"
        threat_id = "2147820123"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 06 07 06 6f 25 00 00 0a 5d 6f 26 00 00 0a 28 08 00 00 06 07 91 73 27 00 00 0a 0c 28 08 00 00 06 07 08 6f 28 00 00 0a 08 6f 29 00 00 0a 61 28 2a 00 00 0a 9c 00 07 17 58 0b 07 28 08 00 00 06 8e 69 fe 04 0d 09 2d b8}  //weight: 1, accuracy: High
        $x_1_2 = "24Y8GYDQ2J6VTJB" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPC_2147820123_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPC!MTB"
        threat_id = "2147820123"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1HBD6LH09KSR" wide //weight: 1
        $x_1_2 = "0xDComp6les" ascii //weight: 1
        $x_1_3 = "0xDBandit2s" ascii //weight: 1
        $x_1_4 = "AsyncTaskMethodBuilder" ascii //weight: 1
        $x_1_5 = "<RussiaVsUkraine>d__" ascii //weight: 1
        $x_1_6 = "_0xDEctopl3smic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_XNFA_2147825479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.XNFA!MTB"
        threat_id = "2147825479"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 01 00 00 6f ?? ?? ?? 0a 09 08 6f ?? ?? ?? 0a 09 18 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 11 04 28 ?? ?? ?? 06 74 6b 00 00 01 6f ?? ?? ?? 0a 17 9a 80 48 00 00 04 23 e2 e6 54 32 00 00 46 40}  //weight: 1, accuracy: Low
        $x_1_2 = "ComputeHash" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPH_2147825661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPH!MTB"
        threat_id = "2147825661"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d b8 06 17 58 0a 00 09 17 58 0d 09 20 00 ?? 01 00 fe 04 13 06 11 06 2d 9b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPH_2147825661_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPH!MTB"
        threat_id = "2147825661"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 04 9a 13 05 11 05 14 fe 01 13 06 11 06 2c 02 2b 48 11 05 2c 12 11 05 7e 75 00 00 0a 16 28 76 00 00 0a 16 fe 03 2b 01 16 13 07 11 07 2c 2a 08 18 8d 03 00 00 01 25 16 11 04 8c 42 00 00 01 a2 25 17 11 05 28 77 00 00 0a 04 da 8c 42 00 00 01 a2 14 28 78 00 00 0a 00 00 00 11 04 17 d6 13 04 11 04 09 31 9a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_NS_2147825863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.NS!MTB"
        threat_id = "2147825863"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 11 04 02 11 04 02 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 11 04 91 28 ?? ?? ?? 06 9c 11 04 17 58 13 04 11 04 7e ?? ?? ?? 04 8e 69 fe 04 13 05 11 05 2d c5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPM_2147825944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPM!MTB"
        threat_id = "2147825944"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 1b 59 1c 58 0d 09 17 fe 04 13 09 11 09 2d c3 06 17 58 0a 00 08 1a 59 1b 58 0c 08 20 00 c6 00 00 fe 04 13 0a 11 0a 2d a5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPM_2147825944_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPM!MTB"
        threat_id = "2147825944"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d c0 06 17 58 0a 00 09 17 58 0d 09 20 00 24 01 00 fe 04 13 06 11 06 2d a3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPM_2147825944_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPM!MTB"
        threat_id = "2147825944"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pastebin.pl/view/raw/997906ff" wide //weight: 1
        $x_1_2 = "GetString" wide //weight: 1
        $x_1_3 = "ExecuteReader" wide //weight: 1
        $x_1_4 = "Mozilla/5.0 (Windows NT 10.0" wide //weight: 1
        $x_1_5 = "LateGet" ascii //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
        $x_1_7 = "get_Ticks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPK_2147826151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPK!MTB"
        threat_id = "2147826151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 45 00 00 04 0a 06 28 ad 00 00 0a 7e 45 00 00 04 02 12 02 6f ae 00 00 0a 2c 04 08 0b de 11 02 17 28 a2 00 00 06 0b de 07 06 28 af 00 00 0a dc 07 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPL_2147826286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPL!MTB"
        threat_id = "2147826286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 1b 59 1c 58 0d 09 17 32 ce 06 17 58 0a 08 1a 59 1b 58 0c 08 20 00 d8 00 00 32 b8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPL_2147826286_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPL!MTB"
        threat_id = "2147826286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UYHGDRWUIYGFIFWHIUWFHFWJKI" wide //weight: 1
        $x_1_2 = "4FFJ587G857GC5DGY44848" wide //weight: 1
        $x_1_3 = "GetObject" wide //weight: 1
        $x_1_4 = "Consolas" wide //weight: 1
        $x_1_5 = "AsyncC" ascii //weight: 1
        $x_1_6 = "GetHashCode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPS_2147826454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPS!MTB"
        threat_id = "2147826454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04 2d c5 06 17 58 0a 00 08 17 58 0c 08 ?? ?? ?? ?? ?? fe 04 13 05 11 05 2d a9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPS_2147826454_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPS!MTB"
        threat_id = "2147826454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7648H28" wide //weight: 1
        $x_1_2 = "F5EJ48FFGHU55T6" wide //weight: 1
        $x_1_3 = "83747" wide //weight: 1
        $x_1_4 = "LoopState32" ascii //weight: 1
        $x_1_5 = "GameForSemestr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPX_2147826948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPX!MTB"
        threat_id = "2147826948"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 06 08 0e 04 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 04 8e 69 fe 04 0d 09 2d e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPX_2147826948_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPX!MTB"
        threat_id = "2147826948"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 07 11 04 07 8e 69 5d 07 11 04 07 8e 69 5d 91 08 11 04 1f 16 5d ?? ?? 00 00 0a 61 ?? ?? 00 00 0a 07 11 04 17 58 07 8e 69 5d 91 ?? ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d ac}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPX_2147826948_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPX!MTB"
        threat_id = "2147826948"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 08 09 16 20 00 10 00 00 6f 55 00 00 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 0e 00 11 04 09 16 11 05 6f 56 00 00 0a 00 00 00 11 05 16 fe 02 13 07 11 07 2d cb}  //weight: 1, accuracy: High
        $x_1_2 = "frmBlackJackSim" ascii //weight: 1
        $x_1_3 = "CompilationRelaxations" ascii //weight: 1
        $x_1_4 = "CategoryMembership" ascii //weight: 1
        $x_1_5 = "DeferredDisposable" ascii //weight: 1
        $x_1_6 = "ScheduledConcurrent" ascii //weight: 1
        $x_1_7 = "B8D25T" wide //weight: 1
        $x_1_8 = "Path_Finder" wide //weight: 1
        $x_1_9 = "Paretherflen.Tucson" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_NYA_2147827128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.NYA!MTB"
        threat_id = "2147827128"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UYHGDRWUIYGFIFWHIUWFHFWJKI" wide //weight: 1
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPB_2147827271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPB!MTB"
        threat_id = "2147827271"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 11 07 07 11 07 9a 1f 10 28 b2 00 00 0a 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d de}  //weight: 1, accuracy: High
        $x_1_2 = "MagicUI.GREEN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPB_2147827271_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPB!MTB"
        threat_id = "2147827271"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 08 09 16 20 00 10 00 00 6f ca 00 00 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 0e 00 11 04 09 16 11 05 6f cb 00 00 0a 00 00 00 11 05 16 fe 02 13 07 11 07 2d cb}  //weight: 1, accuracy: High
        $x_1_2 = "CompilationRelaxations" ascii //weight: 1
        $x_1_3 = "CategoryMembership" ascii //weight: 1
        $x_1_4 = "DeferredDisposable" ascii //weight: 1
        $x_1_5 = "ScheduledConcurrent" ascii //weight: 1
        $x_1_6 = "65736C" wide //weight: 1
        $x_1_7 = "Infusion" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPB_2147827271_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPB!MTB"
        threat_id = "2147827271"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 [0-128] 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Kqqgvokkszmwosobrwgiwoh" wide //weight: 1
        $x_1_3 = "Golden Frog" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "WebRequest" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
        $x_1_7 = "Encoding" ascii //weight: 1
        $x_1_8 = "GetType" ascii //weight: 1
        $x_1_9 = "DynamicInvoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPD_2147827335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPD!MTB"
        threat_id = "2147827335"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 08 09 16 20 00 10 00 00 6f ?? 00 00 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 0e 00 11 04 09 16 11 05 6f ?? 00 00 0a 00 00 00 11 05 16 fe 02 13 07 11 07 2d cb}  //weight: 1, accuracy: Low
        $x_1_2 = "MaxGeneration" ascii //weight: 1
        $x_1_3 = "CompilationRelaxations" ascii //weight: 1
        $x_1_4 = "CategoryMembership" ascii //weight: 1
        $x_1_5 = "DeferredDisposable" ascii //weight: 1
        $x_1_6 = "ScheduledConcurrent" ascii //weight: 1
        $x_1_7 = "B8D25T" wide //weight: 1
        $x_1_8 = "4576656E74526567697374726174696F6E546F6B656E4C" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPE_2147827336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPE!MTB"
        threat_id = "2147827336"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 11 0d 09 18 d8 0d 09 20 a0 86 01 00 fe 02 13 04 11 04 2c 13 09 6c 23 00 00 00 00 00 6a e8 40 5b 28 54 00 00 0a b7 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPE_2147827336_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPE!MTB"
        threat_id = "2147827336"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 06 07 06 6f e6 00 00 0a 5d 6f b0 01 00 0a 28 59 03 00 06 07 91 73 80 02 00 0a 0c 28 59 03 00 06 07 08 6f 81 02 00 0a 08 6f 82 02 00 0a 61 28 83 02 00 0a 9c 00 07 17 58 0b 07 28 59 03 00 06 8e 69 fe 04 0d 09 2d b8}  //weight: 1, accuracy: High
        $x_1_2 = "SSQJRSWYIHTWQAX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_FD_2147828051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.FD!MTB"
        threat_id = "2147828051"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 07 08 02 7b ?? ?? ?? 04 07 1e 5d 6f ?? ?? ?? 0a 6f ?? ?? ?? 06 72 ?? ?? ?? 70 12 01 28 ?? ?? ?? 0a 12 02 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 00 08 17 58 0c 08 03 fe 04 0d 09 2d bf}  //weight: 10, accuracy: Low
        $x_1_2 = {57 1d b6 09 09 0d 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 79 00 00 00 16}  //weight: 1, accuracy: High
        $x_1_3 = "GZipStream" ascii //weight: 1
        $x_1_4 = "GetTypes" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_FE_2147828052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.FE!MTB"
        threat_id = "2147828052"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 09 16 20 00 10 00 00 6f ?? ?? ?? 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 0e 00 11 04 09 16 11 05 6f ?? ?? ?? 0a 00 00 00 11 05 16 fe 02 13 07 11 07 2d cb}  //weight: 10, accuracy: Low
        $x_1_2 = {57 9d b6 29 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 98 00 00 00 37}  //weight: 1, accuracy: High
        $x_1_3 = "GZipStream" ascii //weight: 1
        $x_1_4 = "GetTypes" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_FF_2147828191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.FF!MTB"
        threat_id = "2147828191"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 9f a2 29 09 03 00 00 00 00 00 00 00 00 00 00 01 00 00 00 86 00 00 00 3e}  //weight: 10, accuracy: High
        $x_1_2 = "$98ec7af9-bfad-4fa7-ab9b-4eac5102c9f3" ascii //weight: 1
        $x_1_3 = "GZipStream" ascii //weight: 1
        $x_1_4 = "GetTypes" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_FG_2147828192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.FG!MTB"
        threat_id = "2147828192"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "96Ge96t96Type96" wide //weight: 1
        $x_1_2 = "96A96ss96em96bly" wide //weight: 1
        $x_1_3 = "96En96try96Point" wide //weight: 1
        $x_1_4 = "96I96nvo96ke" wide //weight: 1
        $x_1_5 = "96L96oad" wide //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "CreateInstance" ascii //weight: 1
        $x_1_8 = "Regex" ascii //weight: 1
        $x_1_9 = "Concat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_NYT_2147828702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.NYT!MTB"
        threat_id = "2147828702"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$e93fdb8a-92af-49fe-9735-65433fa10a42" ascii //weight: 1
        $x_1_2 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resource" ascii //weight: 1
        $x_1_3 = "eMail Extractor v2.1r2" ascii //weight: 1
        $x_1_4 = {32 2e 31 72 32 2c 20 c2 a9 20 32 30 30 30 2d 32 30 30 35 20 4d 61 78 70 72 6f 67}  //weight: 1, accuracy: High
        $x_1_5 = "Gmrabnaed.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_FI_2147829197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.FI!MTB"
        threat_id = "2147829197"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$7C18A7B3-A6D7-44A5-BD43-C892F72FB204" ascii //weight: 10
        $x_10_2 = "$e316b126-c783-4060-95b9-aa8ee2e676d7" ascii //weight: 10
        $x_1_3 = "_10_historical_mistakes_in_the_movie_300" wide //weight: 1
        $x_1_4 = "2GHF8KE477558E485BHHEE" wide //weight: 1
        $x_1_5 = "ExampleFull" wide //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
        $x_1_8 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_LokiBot_FJ_2147829198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.FJ!MTB"
        threat_id = "2147829198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 1f a2 09 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 83 00 00 00 28}  //weight: 10, accuracy: High
        $x_1_2 = "$0d14a13a-7e0d-40f2-9223-af67fe045172" ascii //weight: 1
        $x_1_3 = "DebuggingModes" ascii //weight: 1
        $x_1_4 = "GetMethod" ascii //weight: 1
        $x_1_5 = "get_Assembly" ascii //weight: 1
        $x_1_6 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_FL_2147829586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.FL!MTB"
        threat_id = "2147829586"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$8f554f54-ef93-401c-a74f-2af23d7ba65c" ascii //weight: 10
        $x_10_2 = "$b08842c2-105c-4714-a6b5-370119963752" ascii //weight: 10
        $x_1_3 = "J94TR44PV4G" wide //weight: 1
        $x_1_4 = "RZ5858" wide //weight: 1
        $x_1_5 = "PokeBall" wide //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_LokiBot_FM_2147829587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.FM!MTB"
        threat_id = "2147829587"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 9f a2 2b 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 7a 00 00 00 30 00 00 00 83 00 00 00 5f}  //weight: 10, accuracy: High
        $x_1_2 = "$ec8426be-e154-4f0e-8b25-bcf2c8db02b4" ascii //weight: 1
        $x_1_3 = "get_CurrentDomain" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_FN_2147829598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.FN!MTB"
        threat_id = "2147829598"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 1f a2 0b 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 a2 00 00 00 36 00 00 00 c3 00 00 00 4a}  //weight: 10, accuracy: High
        $x_10_2 = {57 df a2 ff 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 a9 00 00 00 40 00 00 00 ee 00 00 00 ae}  //weight: 10, accuracy: High
        $x_1_3 = "$49fe2485-1c3c-42fe-bafd-95aa0814c31f" ascii //weight: 1
        $x_1_4 = "Star_Wars_The_Empire_Strikes_Back_icon" ascii //weight: 1
        $x_1_5 = "XCCVV" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_LokiBot_FP_2147829639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.FP!MTB"
        threat_id = "2147829639"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 1f a2 0b 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 b0 00 00 00 4e 00 00 00 dc 00 00 00 92}  //weight: 10, accuracy: High
        $x_1_2 = "$49fe2485-1c3c-42fe-bafd-95aa0814c31f" ascii //weight: 1
        $x_1_3 = "PerfTester.Properties.Resources.resources" ascii //weight: 1
        $x_1_4 = "get_Assembly" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
        $x_1_6 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_NXH_2147830115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.NXH!MTB"
        threat_id = "2147830115"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VGZ456HE54E448KCS55Q9C" ascii //weight: 1
        $x_1_2 = "XCCVV" ascii //weight: 1
        $x_1_3 = "LogSwitch" ascii //weight: 1
        $x_1_4 = "p0.jO" ascii //weight: 1
        $x_1_5 = "Rfc2898DeriveBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPV_2147830184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPV!MTB"
        threat_id = "2147830184"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 00 1f 11 0d 09 18 5a 0d 09 20 a0 86 01 00 fe 02 13 04 11 04 2c 14 09 6c 23 00 00 00 00 00 6a e8 40 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPO_2147830742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPO!MTB"
        threat_id = "2147830742"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 1f 11 0d 09 18 d8 0d 09 20 a0 86 01 00 fe 02 13 04 11 04 2c 14 09 6c 23 00 00 00 00 00 6a e8 40 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPT_2147830953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPT!MTB"
        threat_id = "2147830953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 7b 2e 01 00 04 04 02 7b 2e 01 00 04 6f 34 00 00 0a 5d 6f a9 01 00 0a 03 61 d2 2a}  //weight: 1, accuracy: High
        $x_1_2 = "Ussr is back" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPW_2147831114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPW!MTB"
        threat_id = "2147831114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovLzgxLjE2MS4yMjkuMTEwL3" wide //weight: 1
        $x_1_2 = "aJDZYqcYFGxMRLp" wide //weight: 1
        $x_1_3 = "Encoding" ascii //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "DownloadString" ascii //weight: 1
        $x_1_7 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPF_2147831301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPF!MTB"
        threat_id = "2147831301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e c0 00 00 04 20 00 00 00 00 97 29 50 00 00 11 00 06 fe 06 d6 01 00 06 73 b9 01 00 0a 28 2c 00 00 2b 28 2d 00 00 2b 0b 07}  //weight: 1, accuracy: High
        $x_1_2 = "MY DAD IS COOL" wide //weight: 1
        $x_1_3 = "Numb In The End" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPN_2147833025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPN!MTB"
        threat_id = "2147833025"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 06 00 00 04 06 28 ?? 00 00 06 d2 9c 09 17 58 0d 09 17 32 cf 06 17 58 0a 08 17 58 0c 08 20 00 4e 01 00 32 bb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RDA_2147833130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RDA!MTB"
        threat_id = "2147833130"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SELECT * FROM Admin WHERE username ='" wide //weight: 1
        $x_1_2 = "SELECT * FROM Admin WHERE password=" wide //weight: 1
        $x_1_3 = "SELECT Admin.username from Admin where username = N'{0}'" wide //weight: 1
        $x_1_4 = "Syst        em.Acti        vator" wide //weight: 1
        $x_1_5 = "Creat     eInsta    nce" wide //weight: 1
        $x_2_6 = {00 08 09 11 04 28 ?? ?? ?? ?? 13 05 11 05 28 ?? ?? ?? ?? 13 06 07 06 11 06 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 07 11 07}  //weight: 2, accuracy: Low
        $x_2_7 = {0a 00 02 16 6f ?? ?? ?? ?? 00 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 38 00 00 0a 28 39 00 00 0a 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 38 00 00 0a 20 00 01 00 00 14 14 18 8d 15 00 00 01 25 16 7e ?? ?? ?? ?? 74 43 00 00 01 a2 25 17 02 7b ?? ?? ?? ?? a2 6f 3a 00 00 0a 26 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RDB_2147833131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RDB!MTB"
        threat_id = "2147833131"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FromBase64" ascii //weight: 1
        $x_1_2 = "GZipStream" ascii //weight: 1
        $x_2_3 = {11 00 2a 00 28 26 00 00 0a 02 6f 27 00 00 0a 13 00}  //weight: 2, accuracy: High
        $x_2_4 = {11 01 14 14 6f 1e 00 00 0a 26 38 ?? ?? ?? ?? 11 00 6f 24 00 00 0a 1b 9a 13 01}  //weight: 2, accuracy: Low
        $x_2_5 = {2a 00 02 74 25 00 00 01 6f 25 00 00 0a 1f 14 9a 13 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RDD_2147833133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RDD!MTB"
        threat_id = "2147833133"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 06 08 06 28 ?? ?? ?? ?? 25 26 69 5d 91 02 08 91 61 d2 6f 1e 00 00 0a 08 1f 10 28 ?? ?? ?? ?? 58 0c 08 02 28}  //weight: 2, accuracy: Low
        $x_1_2 = "SetLastError" ascii //weight: 1
        $x_1_3 = "CloseHandle" ascii //weight: 1
        $x_1_4 = "OpenProcess" ascii //weight: 1
        $x_1_5 = "GetCurrentProcessId" ascii //weight: 1
        $x_1_6 = "LoadLibrary" ascii //weight: 1
        $x_1_7 = "GetProcAddress" ascii //weight: 1
        $x_1_8 = "kernel32.dll" ascii //weight: 1
        $x_1_9 = "user32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RDE_2147833134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RDE!MTB"
        threat_id = "2147833134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 06 02 8e 69 6a 5d d4 02 06 02 8e 69 6a 5d d4 91 03 06 03 8e 69 6a 5d d4 91 61}  //weight: 2, accuracy: High
        $x_2_2 = {02 06 17 6a 58 02 8e 69 6a 5d d4 91}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RDF_2147833881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RDF!MTB"
        threat_id = "2147833881"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2a 72 02 7b ?? ?? ?? ?? 04 02 7b ?? ?? ?? ?? 6f 17 01 00 0a 5d 6f 18 01 00 0a 03 61 d2 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "GetProcAddress" ascii //weight: 1
        $x_1_3 = "LoadLibrary" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPZ_2147836240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPZ!MTB"
        threat_id = "2147836240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 06 11 04 28 91 00 00 0a 11 06 28 91 00 00 0a da 04 d6 1f 1a 5d 13 07 07 11 06 28 91 00 00 0a 11 07 d6 28 92 00 00 0a 28 93 00 00 0a 28 94 00 00 0a 0b 00 2b 10 00 07 11 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPZ_2147836240_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPZ!MTB"
        threat_id = "2147836240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 1f 16 5d 91 61 28 ab 00 00 0a 02 07 17 58 02 8e 69 5d 91 28 ac 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 07 15 58 0b 07 16 2f c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPZ_2147836240_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPZ!MTB"
        threat_id = "2147836240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FFFF00000040000000300009A5D4" wide //weight: 1
        $x_1_2 = "System.Reflection.Assembly" wide //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
        $x_1_6 = "ToByte" ascii //weight: 1
        $x_1_7 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_SRPB_2147836551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.SRPB!MTB"
        threat_id = "2147836551"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 1f 16 5d 91 61 28 ?? ?? ?? 0a 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 07 15 58 0b 07 16 2f c2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CPC_2147840279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CPC!MTB"
        threat_id = "2147840279"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {61 25 0b 19 5e 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2b 30 06 17 62 02 7b ?? ?? ?? ?? 06 8f ?? ?? ?? ?? 03 28 ?? ?? ?? ?? 60 0a 06 20 ?? ?? ?? ?? 34 08 20 ?? ?? ?? ?? 25 2b 06 20 ?? ?? ?? ?? 25 26}  //weight: 5, accuracy: Low
        $x_1_2 = "AMXWrapper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CPD_2147840280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CPD!MTB"
        threat_id = "2147840280"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 3f 00 00 0a 25 26 7e ?? ?? ?? ?? 02 06 6f ?? ?? ?? ?? 25 26 0b 07 28 40 00 00 0a}  //weight: 5, accuracy: Low
        $x_5_2 = {06 07 6f 20 00 00 0a 0c 1f 61 6a 08 28 ?? ?? ?? ?? 25 26 0d 09 28 21 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_3 = "Rnbaccjwl$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CPE_2147840281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CPE!MTB"
        threat_id = "2147840281"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 25 00 00 06 72 30 02 00 70 72 34 02 00 70 6f 59 00 00 0a 0b 00 07 17 8d ?? ?? ?? ?? 25 16 1f 2d 9d 6f ?? ?? ?? ?? 0c 73 ?? ?? ?? ?? 0d}  //weight: 5, accuracy: Low
        $x_5_2 = {09 11 06 08 11 06 9a 1f 10 28 ?? ?? ?? ?? d2 6f ?? ?? ?? ?? 00 11 06 17 58 13 06 11 06 08 8e 69 fe 04 13 07 11 07}  //weight: 5, accuracy: Low
        $x_1_3 = "CV33112" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CPA_2147840293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CPA!MTB"
        threat_id = "2147840293"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 07 6f 09 00 00 0a 13 08 06 6f 0a 00 00 0a 13 09 11 08 11 09 28 ?? ?? ?? ?? 13 09 11 09 28 02 ?? ?? ?? 13 0a 11 0a 6f ?? ?? ?? ?? 13 0b 11 0b}  //weight: 10, accuracy: Low
        $x_1_2 = "59.58.1.63" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CPB_2147840294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CPB!MTB"
        threat_id = "2147840294"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 37 00 00 0a 25 26 7e 0d 00 00 04 02 11 00 6f 2f 00 00 0a 25}  //weight: 5, accuracy: High
        $x_5_2 = {03 28 49 00 00 06 25 26 13 00 38 ?? ?? ?? ?? dd ?? ?? ?? ?? 26 38 ?? ?? ?? ?? 1f 61 6a 03 28 4b 00 00 06 13 00 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CMM_2147841800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CMM!MTB"
        threat_id = "2147841800"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 08 09 91 28 05 00 00 06 13 04 7e 01 00 00 04 11 04 6f 0d 00 00 0a 09 17 58 0d 09 08 8e 69 17 59 32 dd}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CND_2147841801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CND!MTB"
        threat_id = "2147841801"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 65 02 00 06 72 ?? 0b 00 70 72 ?? 0b 00 70 28 26 02 00 06 17 8d ?? 00 00 01 25 16 1f 2d 9d 28 27 02 00 06 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CTT_2147841873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CTT!MTB"
        threat_id = "2147841873"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 33 00 00 06 72 ?? ?? ?? 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 0b 07 6f ?? ?? ?? ?? 17 58 19 5b 0c 08 8d ?? ?? ?? ?? 0d 16 13 07 2b}  //weight: 5, accuracy: Low
        $x_5_2 = {07 19 11 07 5a 6f ?? ?? ?? ?? 13 08 11 08 1f 39 fe 02 13 0a 11 0a 2c 0d 11 08 1f 41 59 1f 0a 58 d1 13 08 2b 08 11 08 1f 30 59 d1 13 08 07 19 11 07 5a 17 58 6f ?? ?? ?? ?? 13 09 11 09 1f 39 fe 02 13 0b 11 0b 2c 0d 11 09 1f 41 59 1f 0a 58 d1 13 09 2b 08 11 09 1f 30 59 d1 13 09 09 11 07 1f 10 11 08 5a 11 09 58 d2 9c 00 11 07 17 58 13 07 11 07 08 fe 04 13 0c 11 0c 2d 84}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_LokiBot_CLF_2147842129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CLF!MTB"
        threat_id = "2147842129"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 f8 02 00 70 6f ?? ?? ?? ?? 74 ?? ?? ?? ?? 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 17 8d ?? ?? ?? ?? 25 16 1f 2d 9d 6f ?? ?? ?? ?? 0b 07 8e}  //weight: 5, accuracy: Low
        $x_5_2 = {08 11 05 07 11 05 9a 1f 10 28 ?? ?? ?? ?? d2 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d db}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_LokiBot_CXE_2147842132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXE!MTB"
        threat_id = "2147842132"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 5a 03 00 70 6f ?? ?? ?? ?? 74 ?? ?? ?? ?? 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 17 8d ?? ?? ?? ?? 25 16 1f 2d 9d 6f ?? ?? ?? ?? 13 01}  //weight: 5, accuracy: Low
        $x_5_2 = {11 02 11 05 11 01 11 05 9a 1f 10 28 ?? ?? ?? ?? d2 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CLO_2147842735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CLO!MTB"
        threat_id = "2147842735"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 72 d7 03 00 70 6f ?? ?? ?? ?? 74 ?? ?? ?? ?? 17 8d ?? ?? ?? ?? 25 16 1f 2d 9d 6f ?? ?? ?? ?? 0b 07 8e 69 8d ?? ?? ?? ?? 0c 16 13 05 2b 17}  //weight: 5, accuracy: Low
        $x_5_2 = {08 11 05 07 11 05 9a 1f 10 28 ?? ?? ?? ?? 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CNDA_2147843332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CNDA!MTB"
        threat_id = "2147843332"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 01 2a 00 03 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 02 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 39 ?? ?? ?? ?? 26 38 ?? ?? ?? ?? 11 02 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 01 38 ?? ?? ?? ?? 38 ?? ?? ?? ?? 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 39 ?? ?? ?? ?? 26 20}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CLQ_2147843365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CLQ!MTB"
        threat_id = "2147843365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 9d 02 00 70 6f ?? ?? ?? ?? 74 ?? ?? ?? ?? 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 17 8d ?? ?? ?? ?? 25 16 1f 2d 9d 6f ?? ?? ?? ?? 13 04 11 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CXJ_2147843367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXJ!MTB"
        threat_id = "2147843367"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 72 bc 07 00 70 6f ?? ?? ?? ?? 74 ?? ?? ?? ?? 0c 08 28 ?? ?? ?? ?? 00 07 08 6f ?? ?? ?? ?? 00 07 06 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 74 ?? ?? ?? ?? 6f ?? ?? ?? ?? 00 07 06 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 74 ?? ?? ?? ?? 6f ?? ?? ?? ?? 00 07 6f ?? ?? ?? ?? 28 ?? ?? ?? ?? 0d 09 6f ?? ?? ?? ?? 17 9a 6f 86 00 00 0a 17 9a 13 04 11 04 16 8c ?? ?? ?? ?? 7e ?? ?? ?? ?? 13 05 11 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CMO_2147843452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CMO!MTB"
        threat_id = "2147843452"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {04 05 5d 91 61 7e 1a 01 00 04 28 5b 02 00 06 03 04 17 58 03 8e 69 5d 91 7e 1b 01 00 04 28 5f 02 00 06 59 11 00 58 11 00 5d d2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CSR_2147843608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CSR!MTB"
        threat_id = "2147843608"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 28 cd 01 00 06 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 26 06 28 ?? ?? ?? ?? 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 26 2b 92 26 07 06 17 8d ?? ?? ?? ?? 0c 08 16 02 a2 08}  //weight: 5, accuracy: Low
        $x_1_2 = "bytes[i] ^= byteArray[i % 16]" wide //weight: 1
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
        $x_1_4 = "System.dll$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CSWI_2147844566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CSWI!MTB"
        threat_id = "2147844566"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 07 06 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 74 ?? ?? ?? ?? 6f ?? ?? ?? ?? 00 07 06 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 74 ?? ?? ?? ?? 6f ?? ?? ?? ?? 00 07 06 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 74 ?? ?? ?? ?? 6f ?? ?? ?? ?? 00 02 28 ?? ?? ?? ?? 02 7b ?? ?? ?? ?? 6f ?? ?? ?? ?? 00 02 02 7b ?? ?? ?? ?? 28 ?? ?? ?? ?? 00 07 6f ?? ?? ?? ?? 28}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPY_2147846028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPY!MTB"
        threat_id = "2147846028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 06 91 11 08 61 07 11 06 17 58 08 5d 91 59 11 09 58 11 09 17 59 5f 13 0a 07 11 06 11 0a d2 9c 00 11 06 17 58 13 06 11 06 08 fe 04 13 0b 11 0b 2d a7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPY_2147846028_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPY!MTB"
        threat_id = "2147846028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 11 05 09 5d 13 08 11 05 09 5b 13 09 08 11 08 11 09 6f 82 00 00 0a 13 0a 07 12 0a 28 83 00 00 0a 6f 84 00 00 0a 00 11 05 17 58 13 05 00 11 05 09 11 04 5a fe 04 13 0b 11 0b 2d c4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RPY_2147846028_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RPY!MTB"
        threat_id = "2147846028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 1d 1f 1e 8d 2a 00 00 01 25 16 72 b0 e3 02 70 a2 25 17 07 a2 25 18 08 a2 25 19 09 a2 25 1a 11 04 a2 25 1b 11 05 a2 25 1c 11 06 a2 25 1d 11 07 a2 25 1e 11 08 a2 25 1f 09 11 09 a2 25 1f 0a 11 0a a2 25 1f 0b 11 0b a2 25 1f 0c 11 0c a2 25 1f 0d 11 0d a2 25 1f 0e 11 0e a2 25 1f 0f 11 0f a2 25 1f 10 11 10 a2 25 1f 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CXRE_2147847093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXRE!MTB"
        threat_id = "2147847093"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 1c 08 07 06 6f ?? ?? ?? ?? 13 09 11 04 12 09 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 06 17 58 0a 06 08 6f ?? ?? ?? ?? fe 04 13 06 11 06 2d d5 07 17 58 0b 07 08 6f ?? ?? ?? ?? fe 04 13 07 11 07 2d be}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CXRF_2147847158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXRF!MTB"
        threat_id = "2147847158"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 05 2b 22 00 07 11 04 11 05 6f ?? ?? ?? ?? 13 06 08 12 06 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 00 00 11 05 17 58 13 05 11 05 07 6f ?? ?? ?? ?? fe 04 13 07 11 07 2d ce 00 11 04 17 58 13 04 11 04 07 6f ?? ?? ?? ?? fe 04 13 08 11 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CXRG_2147847356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXRG!MTB"
        threat_id = "2147847356"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 2f 0a 2b fb 00 28 26 00 00 0a 02 72 ?? ?? ?? ?? 28 0a 00 00 06 6f 27 00 00 0a 28 28 00 00 0a 28 07 00 00 06 17 2d 03 26 de 06 0a 2b fb 26 de 00 06 2c d1 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "https://onedrive.live.com/download?cid=0D0FBFD7EE8A13AB&resid=D0FBFD7EE8A13AB%21189&authkey=AAsuYUuYnYyEKrM" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CXRH_2147847457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXRH!MTB"
        threat_id = "2147847457"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://onedrive.live.com/download?cid=0D0FBFD7EE8A13AB&resid=D0FBFD7EE8A13AB%21179&authkey=AAsMcIFzirq6TzY" wide //weight: 1
        $x_1_2 = "Bblgiijxpozabrbkerkgair.Wfdmrwgyouiqnibs" wide //weight: 1
        $x_1_3 = "FileZilla" wide //weight: 1
        $x_1_4 = "Nbetsczpfwcnpknydqye" wide //weight: 1
        $x_1_5 = "Google Update" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CXRJ_2147847556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXRJ!MTB"
        threat_id = "2147847556"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0b 2b 21 08 06 07 6f ?? ?? ?? ?? 13 0e 12 0e 28 ?? ?? ?? ?? 13 0b 11 05 09 11 0b 9c 09 17 58 0d 07 17 58 0b 07 08 6f ?? ?? ?? ?? fe 04 13 0c 11 0c 2d d0 06 17 58 0a 06 08 6f ?? ?? ?? ?? fe 04 13 0d 11 0d 2d b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_SPC_2147848102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.SPC!MTB"
        threat_id = "2147848102"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 1c 2b 21 75 ?? ?? ?? 01 72 ?? ?? ?? 70 2b 1c 2b 21 2b 26 2b 2b 2b 30 14 14 2b 33 26 2a 28 ?? ?? ?? 0a 2b dd 28 08 00 00 06 2b d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CXRL_2147848124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXRL!MTB"
        threat_id = "2147848124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 09 5b 13 0b 08 11 0a 11 0b 6f ?? ?? ?? ?? 13 0c 07 11 06 12 0c 28 ?? ?? ?? ?? 9c 11 06 17 58 13 06 11 05 17 58 13 05 00 11 05 09 11 04 5a fe 04 13 0d 11 0d 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CXIU_2147848127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXIU!MTB"
        threat_id = "2147848127"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 09 5d 13 08 11 05 09 5b 13 09 08 11 08 11 09 6f ?? ?? ?? ?? 13 0a 07 11 06 12 0a 28 ?? ?? ?? ?? 9c 11 06 17 58 13 06 11 05 17 58 13 05 00 11 05 09 11 04 5a fe 04 13 0b 11 0b 2d c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CXIR_2147848133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXIR!MTB"
        threat_id = "2147848133"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 09 5d 13 09 11 05 09 5b 13 0a 08 11 09 11 0a 6f ?? ?? ?? ?? 13 0b 07 11 06 12 0b 28 ?? ?? ?? ?? 9c 11 06 17 58 13 06 11 05 17 58 13 05 11 05 09 11 04 5a 32 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CXIS_2147848395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXIS!MTB"
        threat_id = "2147848395"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 09 5d 13 08 11 05 09 5b 13 09 08 11 08 11 09 6f ?? ?? ?? ?? 13 0a 07 12 0a 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 00 11 05 17 58 13 05 00 11 05 09 11 04 5a fe 04 13 0b 11 0b 2d c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CXIT_2147848456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXIT!MTB"
        threat_id = "2147848456"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 5b 00 00 70 0a 06 28 0d 00 00 0a 0b 28 3e 00 00 0a 25 26 07 16 07 8e 69 6f 62 00 00 0a 25 26 0a 28 13 00 00 0a 25 26 06 6f 3f 00 00 0a 25 26 0c 1f 61 6a 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CXIW_2147848821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXIW!MTB"
        threat_id = "2147848821"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 00 00 f5 4c 6b 51 24 d1 b0 88 eb 94 05 4f 4d df d9 6c 84 2c b0 ce 39 b3 87 9c 21 00 2e 68 19}  //weight: 1, accuracy: High
        $x_1_2 = "ZWM2MzJmZDktMTY5NC00ZjRhLTliZmYtZjIwNjAwZTM3OTgx" ascii //weight: 1
        $x_1_3 = "Powered by SmartAssembly" ascii //weight: 1
        $x_1_4 = "QndreXplenEl" wide //weight: 1
        $x_1_5 = "Bwkyzezq%" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CXJK_2147849049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXJK!MTB"
        threat_id = "2147849049"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 11 0a 11 09 6f ?? ?? ?? ?? 13 0b 16 13 0c 11 05 11 08 9a 13 0e 11 0e 13 0d 11 0d 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2d 1e 11 0d 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2d 1b 11 0d 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2d 18 2b 21 12 0b 28 ?? ?? ?? ?? 13 0c 2b 16 12 0b 28 ?? ?? ?? ?? 13 0c 2b 0b 12 0b 28 ?? ?? ?? ?? 13 0c 2b 00 07 11 0c 6f ?? ?? ?? ?? 00 00 11 0a 17 58 13 0a 11 0a 09 fe 04 13 0f 11 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CXJK_2147849049_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXJK!MTB"
        threat_id = "2147849049"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 00 44 00 35 00 41 00 39 00 7c 00 7c 00 33 00 7c 00 7c 00 7c 00 30 00 34 00 7c 00 7c 00 7c 00 46 00 46 00 46 00 46}  //weight: 1, accuracy: High
        $x_1_2 = {45 00 31 00 46 00 42 00 41 00 30 00 45 00 7c 00 42 00 34 00 30 00 39 00 43 00 44 00 32 00 31 00 42 00 38}  //weight: 1, accuracy: High
        $x_1_3 = "||0A6F1|||A7" wide //weight: 1
        $x_1_4 = "0B2B|110B2A|" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CXJV_2147849318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXJV!MTB"
        threat_id = "2147849318"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 11 08 11 0a 58 11 09 11 0b 58 6f ?? ?? ?? ?? 13 0c 12 0c 28 ?? ?? ?? ?? 13 0d 11 04 11 06 11 0d 9c 11 06 17 58 13 06 00 11 0b 17 58 13 0b 11 0b 17 fe 04 13 0e 11 0e 2d c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_ASAU_2147849732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.ASAU!MTB"
        threat_id = "2147849732"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 08 07 6f ?? 00 00 0a 13 0e 16 0d 11 0a 06 9a 13 05 11 05 20 [0-4] 28 ?? 00 00 06 28 ?? 00 00 0a 2d 28 11 05 20 [0-4] 28 ?? 00 00 06 28 ?? 00 00 0a 2d 1f 11 05 20 [0-4] 28 ?? 00 00 06 28 ?? 00 00 0a 2d 16 2b 1c 12 0e 28 ?? 00 00 0a 0d 2b 12 12 0e 28 ?? 00 00 0a 0d 2b 08 12 0e 28 ?? 00 00 0a 0d 11 06 09 6f ?? 00 00 0a 08 17 58 0c 08 11 08 32 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_SE_2147850211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.SE!MTB"
        threat_id = "2147850211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 04 2b 1e 07 09 11 04 6f ?? ?? ?? 0a 13 06 08 12 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 04 17 58 13 04 11 04 07 6f ?? ?? ?? 0a 32 d8 09 17 58 0d 09 07 6f ?? ?? ?? 0a 32 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RDI_2147851682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RDI!MTB"
        threat_id = "2147851682"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 04 11 22 58 11 21 11 23 58 6f ?? ?? ?? ?? 13 24 12 24 28 50 01 00 0a 13 25}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CXFF_2147851946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXFF!MTB"
        threat_id = "2147851946"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 05 11 05 17 6f ?? ?? ?? ?? 11 05 08 09 6f ?? ?? ?? ?? 13 06 73 2d 05 00 0a 13 07 11 07 11 06 17 73 ?? ?? ?? ?? 13 08 11 08 07 16 07 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CXII_2147852179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CXII!MTB"
        threat_id = "2147852179"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 11 08 11 04 11 08 18 5a 18 6f ?? ?? ?? ?? 1f 10 28 ?? ?? ?? ?? d2 9c 00 11 08 17 58 13 08 11 08 11 05 8e 69 fe 04 13 09 11 09 2d d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CCAV_2147890364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CCAV!MTB"
        threat_id = "2147890364"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 18 5b 02 07 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 07 18 58 0b 07 02 6f ?? 00 00 0a fe 04 0c 08 2d db}  //weight: 1, accuracy: Low
        $x_1_2 = "QuanLySoTietKiem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CCAW_2147890389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CCAW!MTB"
        threat_id = "2147890389"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 03 61 04 59 20 00 01 00 00 58 0a 2b 00 06}  //weight: 1, accuracy: High
        $x_1_2 = {07 11 0a 11 0f 20 00 01 00 00 5d d2 9c 00 11 09 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CCBI_2147891494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CCBI!MTB"
        threat_id = "2147891494"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 03 8e 69 5d 0b 06 04 6f 7c 00 00 0a 5d 0c 03 07 91 0d 04 08 6f ?? ?? ?? ?? 13 04 02 03 06 28 ?? ?? ?? ?? 13 05 02 09 11 04 11 05 28 ?? ?? ?? ?? 13 06 03 07 11 06 20 ?? ?? ?? ?? 5d d2 9c 00 06 17 59 0a 06 16 fe 04 16 fe 01 13 07 11 07 2d ae}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_SPAD_2147891580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.SPAD!MTB"
        threat_id = "2147891580"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 11 05 9a 13 06 00 11 06 6f ?? ?? ?? 0a 16 fe 01 13 08 11 08 2c 02 2b 34 11 06 72 a9 45 00 70 1f 0c 17 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 09 11 09 2c 02 2b 18 11 06 28 ?? ?? ?? 0a d2 13 07 7e 01 00 00 04 11 07 6f ?? ?? ?? 0a 00 00 11 05 17 58 13 05 11 05 11 04 8e 69 32 a4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CCBL_2147891581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CCBL!MTB"
        threat_id = "2147891581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 03 8e 69 5d 0b 06 04 6f ?? ?? ?? ?? 5d 0c 03 07 91 0d 04 08 6f ?? ?? ?? ?? 13 04 02 03 06 28 ?? ?? ?? ?? 13 05 02 09 11 04 11 05 28 ?? ?? ?? ?? 13 06 03 07 11 06 20 ?? ?? ?? ?? 5d d2 9c 00 06 17 59 0a 06 16 fe 04 16 fe 01 13 07 11 07 2d ae}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_ASFO_2147895248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.ASFO!MTB"
        threat_id = "2147895248"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 18 5b 8d ?? 00 00 01 0b 16 0c 2b 19 07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a d2 9c 08 18 58 0c 08 06 fe 04 0d 09 2d}  //weight: 1, accuracy: Low
        $x_1_2 = "DLPK.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_MBEH_2147895338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.MBEH!MTB"
        threat_id = "2147895338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 08 8e 69 5d 13 07 09 11 06 6f ?? 00 00 0a 5d 13 0b 08 11 07 91 13 0c 11 06 11 0b 6f ?? 00 00 0a 13 0d 02 08 09 28 ?? 00 00 06 13 0e 02 11 0c 11 0d 11 0e 28 ?? 00 00 06 13 0f 08 11 07 11 0f 20 00 01 00 00 5d d2 9c 09 17 59 0d 09 16 2f b0}  //weight: 1, accuracy: Low
        $x_1_2 = "Sudoku.Propertie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_MBFL_2147898273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.MBFL!MTB"
        threat_id = "2147898273"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 0d 07 06 17 58 09 5d 91 13 0e 11 0c 11 0d 61 11 0e 59 20 00 01 00 00 58 13 0f 07 11 06 11 0f 20 00 01 00 00 5d d2 9c 06 17 59 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RDK_2147898708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RDK!MTB"
        threat_id = "2147898708"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "server1" ascii //weight: 1
        $x_1_2 = "Jins sGlobal Inc" ascii //weight: 1
        $x_1_3 = "fasMl09Ny4IU1Z20XUqpCzwoBR9cSZAtKClCcY93fy2fSOlbDx2uzlF3xEsCBcfI2sT15UL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_ARA_2147898777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.ARA!MTB"
        threat_id = "2147898777"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 20 00 01 00 00 13 16 09 17 58 13 17 09 11 04 5d 13 18 11 17 11 04 5d 13 19 07 11 19 91 11 16 58 13 1a 07 11 18 91 13 1b 08 09 1f 16 5d 91 13 1c 11 1b 11 1c 61 13 1d 11 1d 11 1a 59 13 1e 07 11 18 11 1e 11 16 5d d2 9c 09 17 58 0d 00 09 11 04 fe 04 13 1f 11 1f 2d a7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_FK_2147899399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.FK!MTB"
        threat_id = "2147899399"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 b5 a2 3d 09 07 00 00 00 00 00 00 00 00 00 00 01 00 00 00 79 00 00 00 40 00 00 00 5c 00 00 00 36 01 00 00 56}  //weight: 10, accuracy: High
        $x_1_2 = "$f26b454f-9745-4d59-90d4-38d04d9f09e7" ascii //weight: 1
        $x_1_3 = "get_CurrentDomain" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "Reverse" ascii //weight: 1
        $x_1_8 = "CreateInstance" ascii //weight: 1
        $x_1_9 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RDO_2147904419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RDO!MTB"
        threat_id = "2147904419"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {91 61 28 94 00 00 0a 07 11 05 17 58 07 8e 69 5d 91}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RDP_2147905093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RDP!MTB"
        threat_id = "2147905093"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 17 00 00 0a 02 0e 07 0e 04 8e 69 6f 18 00 00 0a 0a 06 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RDQ_2147905176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RDQ!MTB"
        threat_id = "2147905176"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 6f 2d 00 00 0a 6f 2e 00 00 0a 0a 7e ?? ?? ?? ?? 06 25 0b 6f 2f 00 00 0a 00 07 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CCID_2147907796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CCID!MTB"
        threat_id = "2147907796"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 08 07 08 91 11 04 08 1f 16 5d 91 61 07 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_CCIE_2147908470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.CCIE!MTB"
        threat_id = "2147908470"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 91 61 07 08 17 58 11 ?? 5d 91 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_SPFM_2147911366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.SPFM!MTB"
        threat_id = "2147911366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 04 59 0a 06 20 00 01 00 00 58 20 ff 00 00 00 5f 0b}  //weight: 1, accuracy: High
        $x_1_2 = {02 07 11 05 91 11 06 61 11 08 28 ?? ?? ?? 06 13 09 11 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RDR_2147911867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RDR!MTB"
        threat_id = "2147911867"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {61 07 11 04 17 58 07 8e 69 5d 91}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_Y_2147911963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.Y!MTB"
        threat_id = "2147911963"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 1f 10 28 ?? 00 00 0a 03 07 6f ?? 00 00 0a 61 d1 13 04 12 04 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RDS_2147912078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RDS!MTB"
        threat_id = "2147912078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6e 11 4e 20 ff 00 00 00 5f 6a 61 d2 9c 00 11 4a 17 6a 58 13 4a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RDT_2147913281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RDT!MTB"
        threat_id = "2147913281"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 07 11 10 11 11 6e 11 14 20 ff 00 00 00 5f 6a 61 d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_Z_2147913493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.Z!MTB"
        threat_id = "2147913493"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 02 16 03 8e 69 6f ?? ?? 00 0a 0d 09 13 04}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 0b 07 28 ?? ?? 00 0a 04 6f ?? ?? 00 0a 6f ?? ?? 00 0a 0c 06 08 6f ?? ?? 00 0a 00 06 18 6f}  //weight: 2, accuracy: Low
        $x_2_3 = {0c 03 08 73 ?? ?? 00 0a 0d 06 09 06 6f ?? ?? 00 0a 8e 69 6f}  //weight: 2, accuracy: Low
        $x_2_4 = {0a 0b 11 04 07 16 07 8e 69 6f}  //weight: 2, accuracy: High
        $x_2_5 = {06 09 06 6f ?? ?? 00 0a 8e 69 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_X_2147914321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.X!MTB"
        threat_id = "2147914321"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 11 06 11 07 6f ?? 00 00 0a 13 08}  //weight: 4, accuracy: Low
        $x_2_2 = {11 07 17 58 13 07}  //weight: 2, accuracy: High
        $x_2_3 = {11 06 07 fe 04}  //weight: 2, accuracy: High
        $x_2_4 = {0a 16 09 06 1a 28}  //weight: 2, accuracy: High
        $x_2_5 = {06 1a 58 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_RDU_2147915053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.RDU!MTB"
        threat_id = "2147915053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0c 06 91 11 18 61 13 19 11 0c 06 17 58 11 13 5d 91 13 1a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_SPBF_2147916204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.SPBF!MTB"
        threat_id = "2147916204"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {09 59 7e 0e 00 00 04 8e 69 5d 13 0a 02 11 09 91 13 0b 08 18 5d 16 fe 01 13 0c 11 0c 2c 14 00 06 11 09 11 0b 7e 0e 00 00 04 11 0a 91 59 d2 9c 00 2b 12}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_SML_2147917855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.SML!MTB"
        threat_id = "2147917855"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 09 91 11 06 61 11 08 59 20 00 02 00 00 58 13 0a 02 11 0a 28 55 00 00 06 13 0b 02 11 0b 28 56 00 00 06 13 0c 02 11 0c 28 57 00 00 06 13 0d 02 11 0d 28 58 00 00 06 13 0e 07 11 05 11 0e d2 9c 11 05 17 58 13 05 11 05 08 32 88}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_SML_2147917855_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.SML!MTB"
        threat_id = "2147917855"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DC54CY4WPCRYGAFC85GZIF" ascii //weight: 1
        $x_1_2 = "$c8a6a85f-12f9-431d-a126-c94adcb9d296" ascii //weight: 1
        $x_1_3 = "GetXorByte" ascii //weight: 1
        $x_1_4 = "JapaneseTrainer.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_SML_2147917855_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.SML!MTB"
        threat_id = "2147917855"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "58O8557548G552P57HF5R8" ascii //weight: 1
        $x_1_2 = "GetXorByte" ascii //weight: 1
        $x_1_3 = "CalculateKi" ascii //weight: 1
        $x_1_4 = {07 11 09 91 11 06 61 11 08 59 20 00 02 00 00 58 13 0a 02 11 0a 28 55 00 00 06 13 0b 02 11 0b 28 56 00 00 06 13 0c 02 11 0c 28 57 00 00 06 13 0d 02 11 0d 28 58 00 00 06 13 0e 07 11 05 11 0e d2 9c 11 05 17 58 13 05 11 05 08 32 88}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_SJPF_2147920137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.SJPF!MTB"
        threat_id = "2147920137"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 11 05 11 06 6f ?? ?? ?? 0a 13 07 08 12 07 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 12 07 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 12 07 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 07 08 20 ?? ?? ?? 00 28 ?? ?? ?? 06 00 08 6f ?? ?? ?? 0a 00 00 11 06 17 58 13 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_SK_2147927107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.SK!MTB"
        threat_id = "2147927107"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$84ecaffb-3eb4-4974-ab95-f21dc4b0d4bb" ascii //weight: 2
        $x_2_2 = "NJnNoi887.Properties.Resources" ascii //weight: 2
        $x_2_3 = "NJnNoi887.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_SVCB_2147929865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.SVCB!MTB"
        threat_id = "2147929865"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 04 11 04 09 07 08 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 11 05 06 16 06 8e 69 6f ?? 00 00 0a 73 ?? 00 00 0a 25 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_SDGB_2147930834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.SDGB!MTB"
        threat_id = "2147930834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 19 8d 3b 00 00 01 25 16 07 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 07 1e 63 20 ff 00 00 00 5f d2 9c 25 18 07 20 ff 00 00 00 5f d2 9c 6f ?? 01 00 0a 09}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_ALO_2147931061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.ALO!MTB"
        threat_id = "2147931061"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8e 69 17 59 0c 2b 19 0b 2b f5 06 07 91 0d 06 07 06 08 91 9c 06 08 09 9c 07 17 58 0b 08 17 59 0c 07 08 32 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_NB_2147931426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.NB!MTB"
        threat_id = "2147931426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {28 5b 00 00 06 25 26 11 01 16 11 01 8e 69 28 5c 00 00 06 25 26 13 00 38 cd ff ff ff}  //weight: 3, accuracy: High
        $x_1_2 = "Host-Server-Konfiguration" ascii //weight: 1
        $x_1_3 = "DE_PAGE.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_ALB_2147931830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.ALB!MTB"
        threat_id = "2147931830"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 09 16 1a 09 14 13 16 12 16 11 05 11 04 28 ?? 00 00 06 26 08 02 08 1f 3c d6 6a 1a 6a 28 ?? 00 00 06 d6 13 09 02 11 09 1f 34 d6 6a 1a 6a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_ALB_2147931830_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.ALB!MTB"
        threat_id = "2147931830"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 13 07 2b 15 00 07 11 07 07 11 07 94 03 5a 1f 64 5d 9e 00 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d de}  //weight: 2, accuracy: High
        $x_1_2 = "Student_Housing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_AUJ_2147932021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.AUJ!MTB"
        threat_id = "2147932021"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0b 06 20 17 24 b2 32 28 01 00 00 06 0c 12 02 28 10 00 00 0a 74 01 00 00 1b 0d 72 01 00 00 70 09 6f 11 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_AYA_2147935289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.AYA!MTB"
        threat_id = "2147935289"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Http Debugger has been detected on ur computer, since it can be used for malicious ending" wide //weight: 2
        $x_2_2 = "server.Resources.resources" ascii //weight: 2
        $x_1_3 = "HTTPDebuggerPro\\HTTPDebuggerBrowser.dll" wide //weight: 1
        $x_1_4 = "discord.gg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_AY_2147940958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.AY!MTB"
        threat_id = "2147940958"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 11 05 02 11 05 91 06 61 08 11 04 91 61 b4 9c 1e 13 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_MBZ_2147942072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.MBZ!MTB"
        threat_id = "2147942072"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {52 00 50 00 53 00 5f 00 47 00 61 00 6d 00 65}  //weight: 2, accuracy: High
        $x_1_2 = "Barzzers" wide //weight: 1
        $x_1_3 = {78 00 78 00 78 00 78 00 78 00 78 00 78 00 00 1b 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73}  //weight: 1, accuracy: High
        $x_1_4 = "PronHub" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LokiBot_BAA_2147951313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiBot.BAA!MTB"
        threat_id = "2147951313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 08 17 73 35 00 00 0a 13 04 11 04 06 16 06 8e 69 ?? ?? ?? ?? ?? de 0c 11 04 2c 07 11 04 6f 27 00 00 0a dc 02 72 cb 00 00 70 72 ed 00 00 70 6f 3c 00 00 0a 09 6f 37 00 00 0a 28 38 00 00 0a de 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

