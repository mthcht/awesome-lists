rule Trojan_MSIL_Tiny_H_2147745198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.H!MTB"
        threat_id = "2147745198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 00 00 11 00 28 ?? ?? ?? ?? 0a 06 16 28 ?? ?? ?? ?? 26 72 ?? ?? ?? ?? 0b 07 28 ?? ?? ?? ?? 0c 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 00 08 28 ?? ?? ?? ?? 00 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "ExploitShellcodeExec" ascii //weight: 1
        $x_1_3 = "excutando" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MSIL_Tiny_PE_2147766329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.PE!MTB"
        threat_id = "2147766329"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JScriptImport" ascii //weight: 1
        $x_1_2 = "JScriptPackage" ascii //weight: 1
        $x_1_3 = "ExecuteProcess" ascii //weight: 1
        $x_1_4 = "SibClr" wide //weight: 1
        $x_1_5 = "SibCa" wide //weight: 1
        $x_1_6 = ".vbs //e:vbscript //NOLOGO" wide //weight: 1
        $x_1_7 = "=SibClr, Version=6.0.6.0, Culture=neutral, PublicKeyToken=null" ascii //weight: 1
        $x_1_8 = "ISystem, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_A_2147778972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.A!MTB"
        threat_id = "2147778972"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 2d 1c 7e 07 ?? ?? 04 7e ?? ?? ?? 04 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 28 ?? ?? ?? 0a 26 2b 27 7e ?? ?? ?? 04 18 2f 0e 7e ?? ?? ?? 04 17 d6 80 ?? ?? ?? 04 2b 11 16 80 ?? ?? ?? 04 7e ?? ?? ?? 04 28 ?? ?? ?? 0a 26 2b 2c 16}  //weight: 10, accuracy: Low
        $x_5_2 = "Select CommandLine from Win32_Process where Name='{0}'" ascii //weight: 5
        $x_4_3 = "AES_Decryptor" ascii //weight: 4
        $x_3_4 = "WDLoop" ascii //weight: 3
        $x_3_5 = "CheckProc" ascii //weight: 3
        $x_3_6 = "Watchdog" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Tiny_AC_2147779308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.AC!MTB"
        threat_id = "2147779308"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 18 5b 8d 03 ?? ?? 01 0a 16 0b 38 ?? ?? ?? 00 06 07 18 5b 02 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 07 18 58 0b 07 02}  //weight: 10, accuracy: Low
        $x_4_2 = "zirikatu" ascii //weight: 4
        $x_4_3 = "burutu" ascii //weight: 4
        $x_3_4 = "HexStringToByteArray" ascii //weight: 3
        $x_2_5 = "GetConsoleWindow" ascii //weight: 2
        $x_2_6 = "ret1ArgDelegate" ascii //weight: 2
        $x_2_7 = "{0:x}" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Tiny_AS_2147781319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.AS!MTB"
        threat_id = "2147781319"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 09 16 20 a0 86 01 00 6f ?? ?? ?? 0a 13 07 11 07 2c 19 11 07 15 2e 14 11 05 09 16 11 07 6f ?? ?? ?? 0a 11 04 11 07 58 13 04 2b d4}  //weight: 10, accuracy: Low
        $x_5_2 = "https://strak.xyz/log2.php?name={0}&rec={1}" ascii //weight: 5
        $x_5_3 = "SendLogMessage" ascii //weight: 5
        $x_5_4 = "defenderutility" ascii //weight: 5
        $x_3_5 = "simpleDownloader" ascii //weight: 3
        $x_3_6 = "taskhostms" ascii //weight: 3
        $x_3_7 = "taskhostms.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_BCE_2147788128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.BCE!MTB"
        threat_id = "2147788128"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 30 06 00 7c 00 00 00 01 00 00 11 28 04 00 00 0a 72 01 00 00 70 28 02 00 00 06 6f 05 00 00 0a 0a 1a 8d 01 00 00 01 0c 08 16 72 ?? 00 00 70 a2 08 17 7e 06 00 00 0a a2 08 18 72 ?? ?? 00 70 28 02 00 00 06 a2 08 19 17 8c 08 00 00 01 a2 08 0b 20 f4 01 00 00 28 07 00 00 0a 06 72 ?? 01 00 70 6f 08 00 00 0a 72 ?? ?? 00 70 20 00 01 00 00 14 14 07 74 01 00 00 1b 6f 09 00 00 0a 26 20 f4 01 00 00 28 07 00 00 0a 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "https://cdn.discordapp.com/attachments/8" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_BEY_2147789542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.BEY!MTB"
        threat_id = "2147789542"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppData\\Roaming\\Cyber_Crypter" ascii //weight: 1
        $x_1_2 = "https://cdn.discordapp.com/attachments/877689582395719724/877689610287861840/winomoera.dll" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_BBW_2147794861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.BBW!MTB"
        threat_id = "2147794861"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 29 00 00 0a 72 15 00 00 70 6f 2a 00 00 0a 80 08 00 00 04 7e 08 00 00 04 17 8d ?? 00 00 01 25 16 1f 7c 9d 6f 2b 00 00 0a 16 9a 80 09 00 00 04 7e 08 00 00 04 17 8d ?? 00 00 01 25 16 1f 7c 9d 6f 2b 00 00 0a 17 9a 80 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 04 28 04 00 00 06 6f 2c 00 00 0a 7e 09 00 00 04 1f 1a 28 2d 00 00 0a 72 59 00 00 70 28 2e 00 00 0a 6f 2f 00 00 0a 28 04 00 00 06 6f 2c 00 00 0a 7e 0a 00 00 04 1f 1a 28 2d 00 00 0a 72 67 00 00 70 28 2e 00 00 0a 6f 2f 00 00 0a}  //weight: 1, accuracy: High
        $x_1_3 = "WORM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_DA_2147795867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.DA!MTB"
        threat_id = "2147795867"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 16 11 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 06 11 04 11 06 6f ?? ?? ?? 0a 13 07 09 11 07 6f ?? ?? ?? 0a 26 00 11 05 17 d6 13 05 11 05 1e 31 d0}  //weight: 1, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "/cdn.discordapp.com/attachments/" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_AB_2147795875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.AB!MTB"
        threat_id = "2147795875"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SecurityProtocolType" ascii //weight: 3
        $x_3_2 = "DownloadData" ascii //weight: 3
        $x_3_3 = "IOQiwbeqibwqwexqwev" ascii //weight: 3
        $x_3_4 = "DynamicInvoke" ascii //weight: 3
        $x_3_5 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegSvcs.exe" ascii //weight: 3
        $x_3_6 = "cdn.discordapp" ascii //weight: 3
        $x_3_7 = "ServicePointManager" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_AH_2147798635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.AH!MTB"
        threat_id = "2147798635"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ok.exe" ascii //weight: 1
        $x_1_2 = "StartUP" ascii //weight: 1
        $x_1_3 = "http://rghost.net,http://www.filetolink.com,https://pomf.cat,,http://example.com/file1.exe,http://example.net/file2.exe" wide //weight: 1
        $x_1_4 = "829d9fdd" wide //weight: 1
        $x_1_5 = "fgdfhdfhd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_MA_2147838778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.MA!MTB"
        threat_id = "2147838778"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 b3 00 00 70 28 06 00 00 06 de 03}  //weight: 1, accuracy: High
        $x_1_2 = "bedfb417-a2df-4ae5-bb1c-1b8c00b3eb71" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_MA_2147838778_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.MA!MTB"
        threat_id = "2147838778"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "Fixx.Properties" ascii //weight: 5
        $x_5_2 = "74b03f90-83ac-4d7d-83f2-324651a6873e" ascii //weight: 5
        $x_3_3 = {2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 [0-20] 2e 00 76 00 62 00 73 00}  //weight: 3, accuracy: Low
        $x_1_4 = "This application could not be started." wide //weight: 1
        $x_1_5 = "GetTempPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_SPQS_2147838942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.SPQS!MTB"
        threat_id = "2147838942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 06 17 7e 06 00 00 0a a2 11 06 18 06 72 e7 00 00 70 6f ?? ?? ?? 0a a2 11 06 19 17 8c 0b 00 00 01 a2 11 06 0d 06}  //weight: 2, accuracy: Low
        $x_1_2 = "KUREK://codiumsecurity.com/RunPe.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_SPQX_2147838944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.SPQX!MTB"
        threat_id = "2147838944"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 05 07 11 04 11 05 1b 58 09 11 05 59 20 84 13 00 00 32 07 20 00 10 00 00 2b 04 09 11 05 59 16 6f ?? ?? ?? 0a 58 13 05 00 11 05 09 fe 04 13 08 11 08 2d cb}  //weight: 3, accuracy: Low
        $x_1_2 = "CsharpDemo.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_NEAA_2147839742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.NEAA!MTB"
        threat_id = "2147839742"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 72 01 00 00 70 0a 28 03 00 00 06 0b 28 03 00 00 06 26 07 06 28 02 00 00 06 00 07 28 04 00 00 06 00 2a}  //weight: 10, accuracy: High
        $x_5_2 = "https://raw.githubusercontent.com/db-host192/db-host192.github.io" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_ABLX_2147842971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.ABLX!MTB"
        threat_id = "2147842971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 13 04 28 ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 13 05 09 11 05 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 13 06 11 06 06 16 06 8e 69 6f ?? ?? ?? 0a 13 07 28 ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a 13 08 11 08 13 0a de 14 09 2c 06 09 6f ?? ?? ?? 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_EH_2147843635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.EH!MTB"
        threat_id = "2147843635"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System.Threading.Tasks" ascii //weight: 1
        $x_1_2 = "System.Security.Permissions" ascii //weight: 1
        $x_1_3 = "get_Result" ascii //weight: 1
        $x_1_4 = "HttpClient" ascii //weight: 1
        $x_1_5 = "http://cleaning.homesecuritypc.com/packages" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_RSY_2147847092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.RSY!MTB"
        threat_id = "2147847092"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 28 0e 00 00 06 28 01 00 00 2b 28 02 00 00 2b 0a de 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_ABVA_2147847373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.ABVA!MTB"
        threat_id = "2147847373"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 72 01 00 00 70 28 ?? 00 00 0a 72 b8 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 00 72 cc 00 00 70 72 d4 00 00 70 73 ?? 00 00 0a 25 28 ?? 00 00 0a 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 28 ?? 00 00 0a 26 1f 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_PSRZ_2147850761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.PSRZ!MTB"
        threat_id = "2147850761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 06 28 15 00 00 0a 26 2b 54 73 16 00 00 0a 13 0a 00 00 11 0a 07 11 04 6f 17 00 00 0a 00 00 de 1b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_SPWE_2147888629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.SPWE!MTB"
        threat_id = "2147888629"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 03 00 00 0a 0a 73 04 00 00 0a 13 05 11 05 72 01 00 00 70 6f ?? ?? ?? 0a 11 05 17 6f ?? ?? ?? 0a 11 05 16 6f ?? ?? ?? 0a 11 05 16 6f ?? ?? ?? 0a 11 05 0b 06 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_NTN_2147892112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.NTN!MTB"
        threat_id = "2147892112"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 3c 00 00 0a 02 6f ?? ?? ?? 0a 13 00 20 ?? ?? ?? 00 7e ?? ?? ?? 04 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff 73 ?? ?? ?? 0a 25 17 6f ?? ?? ?? 0a 25 18 6f ?? ?? ?? 0a 11 00 11 00 1f 10 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 13 07 20 ?? ?? ?? 00 7e ?? ?? ?? 04 39 ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "CSharpShellcodeLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_SPQI_2147895484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.SPQI!MTB"
        threat_id = "2147895484"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 39 16 1f 2c 9d 11 39 17 6f ?? ?? ?? 0a 13 13 11 13 8e 69 8d ?? ?? ?? 01 13 14 16 13 15 2b 15 11 14 11 15 11 13 11 15 9a 28 ?? ?? ?? 0a 9c 11 15 17 58 13 15 11 15 11 13 8e 69 32 e3}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_AT_2147895773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.AT!MTB"
        threat_id = "2147895773"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 11 06 6f 06 00 00 0a 17 6f 08 00 00 0a 11 06 6f 06 00 00 0a 16 6f 09 00 00 0a 11 06 6f 06 00 00 0a 17 6f 0a 00 00 0a 11 06 6f 06 00 00 0a 17 6f 0b 00 00 0a 11 06 6f 06 00 00 0a 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_NBL_2147896416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.NBL!MTB"
        threat_id = "2147896416"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 05 91 9c 07 11 05 09 9c 07 11 04 91 07 11 05 91 58 20 00 01 00 00 5d 13 07 02 11 06 8f 10 00 00 01 25 71 10 00 00 01 07 11 07 91 61 d2 81 10 00 00 01 11 06 17 58 13 06 11 06 02 16 6f 13 00 00 0a 32 98 02 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_AMCA_2147898996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.AMCA!MTB"
        threat_id = "2147898996"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 2d f7 00 2b 57 72 ?? ?? ?? 70 2b 5a 2b 62 38 ?? 00 00 00 38 ?? 00 00 00 8e 69 38 ?? 00 00 00 16 38 ?? 00 00 00 2b 1e 2b 69 08 91 0d 17 2c 25 06 08 06 07 08 59 17 59 91 9c 06 07 08 59 17 59 09 9c 08 17 58 0c 08 07 15 2c f9 18 5b 1d 2c f4 1e 2c f5 32 d3 16 2d e2 06 13 04 de 42}  //weight: 2, accuracy: Low
        $x_1_2 = "HttpClient" ascii //weight: 1
        $x_1_3 = "GetByteArrayAsync" ascii //weight: 1
        $x_1_4 = "get_Result" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_PSCC_2147899334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.PSCC!MTB"
        threat_id = "2147899334"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {73 0f 00 00 0a 25 72 01 00 00 70 6f 10 00 00 0a 25 72 75 00 00 70 6f 11 00 00 0a 25 16 6f 12 00 00 0a 28 13 00 00 0a 6f 14 00 00 0a 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_PTCK_2147901143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.PTCK!MTB"
        threat_id = "2147901143"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2c 5a 00 00 06 28 ?? 00 00 0a 0c 08 6f 14 00 00 0a 0d 09 14 28 ?? 00 00 0a 13 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_AMCC_2147901983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.AMCC!MTB"
        threat_id = "2147901983"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 08 18 58 0c 08 06 32 e4}  //weight: 1, accuracy: Low
        $x_1_2 = "456E747279506F696E74" wide //weight: 1
        $x_1_3 = "496E766F6B65" wide //weight: 1
        $x_1_4 = {44 04 39 04 39 04 44 04 39 04 39 04 44 04 44 04 44 04 39 04 39 04 44 04 39 04 39 04 44 04 44 04 44 04 39 04 39 04 44 04 44 04 39 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_PTJF_2147903519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.PTJF!MTB"
        threat_id = "2147903519"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 0f 00 00 0a 02 03 28 ?? 00 00 0a 00 03 1c 28 ?? 00 00 0a 00 03 17 8d 16 00 00 01 25 16 1f 5c 9d 6f 14 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_RZ_2147913003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.RZ!MTB"
        threat_id = "2147913003"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 2a 11 05 17 58 13 05 11 05 11 04 8e 69 32 bd 08 17 58 0c 08 07 8e 69 32 a7 16 2a}  //weight: 1, accuracy: High
        $x_1_2 = "windows explorer tracker" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_EM_2147917811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.EM!MTB"
        threat_id = "2147917811"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 06 07 11 05 11 06 1b 58 11 04 11 06 59 20 00 10 00 00 3c 0a 00 00 00 11 04 11 06 59 38 05 00 00 00 20 00 10 00 00 16 6f 07 00 00 0a 58 13 06 11 06 11 04 3f c7 ff ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_EAB_2147929662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.EAB!MTB"
        threat_id = "2147929662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 08 06 28 10 00 00 06 00 08 06 28 11 00 00 06 00 08 06 28 12 00 00 06 00 00 08 17 58 0c 08 20 e8 03 00 00 fe 04 0d 09 2d d6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_EAEU_2147936237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.EAEU!MTB"
        threat_id = "2147936237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 06 07 02 07 91 03 07 03 6f ?? ?? ?? ?? ?? ?? ?? 00 00 0a 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d da}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_NIT_2147943276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.NIT!MTB"
        threat_id = "2147943276"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 72 f1 00 00 70 0a 7e 1d 00 00 0a 06 17 6f ?? 00 00 0a 0b 00 28 1f 00 00 0a 6f ?? 00 00 0a 0c 07 72 4d 01 00 70 08 6f ?? 00 00 0a 00 00 de 12}  //weight: 2, accuracy: Low
        $x_1_2 = {11 07 11 08 9a 13 05 00 11 05 6f ?? 00 00 0a 2c 18 11 05 6f ?? 00 00 0a 6f ?? 00 00 0a 72 57 00 00 70 6f ?? 00 00 0a 2b 01 17 13 09 11 09 2d 51 00 00 72 5f 00 00 70 11 05 6f ?? 00 00 0a 28 ?? 00 00 0a 00 06 07 08 09 28 ?? 00 00 06 00 11 05 6f ?? 00 00 0a 6f ?? 00 00 0a 06 07 08 09 28 ?? 00 00 06 00 00 de 18 13 06 00 72 93 00 00 70 11 06 6f ?? 00 00 0a 28 ?? 00 00 0a 00 00 de 00 00 00 00 11 08 17 58 13 08 11 08 11 07 8e 69 fe 04 13 09 11 09 3a 67 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_GVA_2147944038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.GVA!MTB"
        threat_id = "2147944038"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 28 37 00 00 0a 2d 0c 06 08 6f 38 00 00 0a 6f 39 00 00 0a 07 6f 3a 00 00 0a 25 0c 2d e2 06 0d de 0a 07 2c 06 07 6f 27 00 00 0a dc 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_ZKU_2147946134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.ZKU!MTB"
        threat_id = "2147946134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 20 ff 00 00 00 33 53 07 6f ?? 00 00 0a 13 04 11 04 2d 0d 08 20 ff 00 00 00 6f ?? 00 00 0a 2b 42 1a 8d 39 00 00 01 13 05 11 05 16 11 04 d2 9c 07 11 05 17 19 6f ?? 00 00 0a 26 11 05 16 28 ?? 00 00 0a 13 06 11 06 8d 39 00 00 01 13 07 08 11 07 16 11 06 6f ?? 00 00 0a 2b 08 08 09 d2 6f ?? 00 00 0a 07 6f ?? 00 00 0a 25 0d 15 33 92}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_NITF_2147946883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.NITF!MTB"
        threat_id = "2147946883"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {d8 00 00 70 0a 72 ?? 00 00 70 06 02 28 ?? 00 00 0a 0b 73 36 00 00 0a 25 72 ?? 00 00 70 6f ?? 00 00 0a 25 72 ?? 01 00 70 07 28 ?? 00 00 0a 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 72 ?? 00 00 70 6f ?? 00 00 0a 28 ?? 00 00 0a 0c 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 2c 1b 72 ?? 02 00 70 08 6f ?? 00 00 0a 8c 32 00 00 01 28 ?? 00 00 0a 73 3f 00 00 0a 7a de 0a}  //weight: 3, accuracy: Low
        $x_2_2 = {72 25 00 00 70 0a 1f 24 28 ?? 00 00 0a 72 b8 00 00 70 28 ?? 00 00 0a 0b 73 2b 00 00 0a 0c 07 28 ?? 00 00 06 08 06 07 6f ?? 00 00 0a de 0a 08 2c 06 08 6f ?? 00 00 0a dc 07 73 2e 00 00 0a 25 17 6f ?? 00 00 0a 25 72 cc 00 00 70 6f ?? 00 00 0a 26 de 19}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tiny_AD_2147959781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tiny.AD!AMTB"
        threat_id = "2147959781"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "statx.exe" ascii //weight: 2
        $x_1_2 = "C:\\Program Files\\Windows NT\\Accessories\\bj.exe" ascii //weight: 1
        $x_2_3 = "http://14.55.107.10" ascii //weight: 2
        $x_1_4 = "statx.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

