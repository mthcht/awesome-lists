rule Trojan_MSIL_Coinminer_GA_2147751997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.GA!MTB"
        threat_id = "2147751997"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "watchdog" ascii //weight: 10
        $x_5_2 = "\\root\\cimv2" ascii //weight: 5
        $x_5_3 = "Select CommandLine from Win32_Process where Name='{0}'" ascii //weight: 5
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "CreateNoWindow" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "CreateEncryptor" ascii //weight: 1
        $x_1_8 = "GetTempPath" ascii //weight: 1
        $x_1_9 = "Combine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Coinminer_SBR_2147760647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.SBR!MSR"
        threat_id = "2147760647"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "http://mrbftp.xyz" wide //weight: 4
        $x_1_2 = "SecurityService.Unzip" ascii //weight: 1
        $x_1_3 = "WindowsSecurityService.pdb" ascii //weight: 1
        $x_1_4 = "vihansoft.ir" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Coinminer_SBR_2147760647_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.SBR!MSR"
        threat_id = "2147760647"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://mrbfile.xyz" wide //weight: 1
        $x_1_2 = "UHJvY2Vzc0hhY2tlcg" wide //weight: 1
        $x_1_3 = "MRB_ADMIN" wide //weight: 1
        $x_1_4 = "dGFza21ncg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Coinminer_SBR_2147760647_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.SBR!MSR"
        threat_id = "2147760647"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vihansoft.ir" wide //weight: 1
        $x_1_2 = "SecurityService.Unzip" ascii //weight: 1
        $x_1_3 = "WindowsSecurityService.pdb" ascii //weight: 1
        $x_1_4 = "version.txt" wide //weight: 1
        $x_1_5 = "syslib.dll" wide //weight: 1
        $x_1_6 = "DownloadDLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Coinminer_SBR_2147760647_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.SBR!MSR"
        threat_id = "2147760647"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://systemfile.online" wide //weight: 2
        $x_1_2 = "54.36.10.73" wide //weight: 1
        $x_1_3 = "pcadmin.online" wide //weight: 1
        $x_1_4 = "win.dll" wide //weight: 1
        $x_1_5 = "WindowsSecurityService.pdb" wide //weight: 1
        $x_1_6 = "WindowsRunner.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Coinminer_SBR_2147760647_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.SBR!MSR"
        threat_id = "2147760647"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://iplogger.com" wide //weight: 1
        $x_1_2 = "https://github.com/Alexuiop1337/Trojan-Downloader/raw/master/fee.exe" wide //weight: 1
        $x_1_3 = "C choice /C Y /N /D Y /T 3 & Del" wide //weight: 1
        $x_1_4 = "MSOSecurity" wide //weight: 1
        $x_1_5 = "Streamm.exe" wide //weight: 1
        $x_1_6 = "PredatorTheMiner.Properties.Resources" wide //weight: 1
        $x_1_7 = "ProcessHacker" wide //weight: 1
        $x_1_8 = "--url={0} --user={1} --pass={4} --threads 5 --donate-level=1 --keepalive --retries=5 --max-cpu-usage={3}" wide //weight: 1
        $x_1_9 = "SecurityIdentifier" ascii //weight: 1
        $x_1_10 = "PredatorTheMiner.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Trojan_MSIL_Coinminer_DA_2147782197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.DA!MTB"
        threat_id = "2147782197"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WlVSMVMgVmFsb3JhbnQgSGFjayB2MS42" ascii //weight: 1
        $x_1_2 = "DebuggerPresent" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CopyClient" ascii //weight: 1
        $x_1_5 = "_Encrypted$" ascii //weight: 1
        $x_1_6 = "ConnectionList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Coinminer_DA_2147782197_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.DA!MTB"
        threat_id = "2147782197"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "-watchdog.exe" ascii //weight: 20
        $x_1_2 = "set_IsBackground" ascii //weight: 1
        $x_1_3 = "Confuser.Core" ascii //weight: 1
        $x_1_4 = "IsLogging" ascii //weight: 1
        $x_1_5 = "Debugger" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
        $x_1_8 = "FailFast" ascii //weight: 1
        $x_1_9 = "get_IsAlive" ascii //weight: 1
        $x_1_10 = "GetString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Coinminer_UF_2147809031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.UF!MTB"
        threat_id = "2147809031"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetType" ascii //weight: 1
        $x_1_2 = "GetMethod" ascii //weight: 1
        $x_1_3 = "AES_Decryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "ToString" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
        $x_1_8 = "GetString" ascii //weight: 1
        $x_1_9 = "CreateDecryptor" ascii //weight: 1
        $x_1_10 = {00 62 75 66 66 65 72 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 69 6e 70 75 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Coinminer_JRIMI_2147812862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.JRIMI!MTB"
        threat_id = "2147812862"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1f 64 73 53 00 00 0a 0a 73 54 00 00 0a 13 05 11 05 20 00 01 00 00 2b 18 11 05 17 2b 05 11 05 0b 2b 07 6f ?? ?? ?? 0a 2b f4 03 2d 02 2b 09 2b 3a 6f ?? ?? ?? 0a 2b e1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Coinminer_AVSF_2147818350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.AVSF!MTB"
        threat_id = "2147818350"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 18 5b 02 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 08 18 58 0c 08 06 32 e4 07 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "doberman" wide //weight: 1
        $x_1_3 = "a8doSuDitOz1hZe#" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Coinminer_MF_2147823227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.MF!MTB"
        threat_id = "2147823227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a d4 8d 58 00 00 01 2b 0e 02 06 16 06 8e 69 6f ?? ?? ?? 0a 26 2b 03 0a 2b ef 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "ToCharArray" ascii //weight: 1
        $x_1_3 = "base64EncodedData" ascii //weight: 1
        $x_1_4 = "RemoveRepeated" ascii //weight: 1
        $x_1_5 = "Base64Decode" ascii //weight: 1
        $x_1_6 = "IAsyncStateMachine" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "MemoryStream" ascii //weight: 1
        $x_1_10 = "GetDrives" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Coinminer_EB_2147835056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.EB!MTB"
        threat_id = "2147835056"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System.Security.Cryptography.AesCryptoServiceProvider" wide //weight: 1
        $x_1_2 = "4jQFPTJfNMBUkNyGa9.H7N74x1Mc0yuC5DJfS" wide //weight: 1
        $x_1_3 = "Js1q0Ql0Zs5pxoZUTH.d9eZKW9Sed2kEOcd6F" wide //weight: 1
        $x_1_4 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_1_5 = "GetDelegateForFunctionPointer" wide //weight: 1
        $x_1_6 = "Q8gmtVog0EASfN4hD6.NHi3XjvYJAgn09IVuq" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Coinminer_RJ_2147838174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.RJ!MTB"
        threat_id = "2147838174"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nuredgbcp\\" ascii //weight: 1
        $x_1_2 = "LanmKtmRm.exe" ascii //weight: 1
        $x_1_3 = "Landmine.exe" ascii //weight: 1
        $x_1_4 = "CommandLineEventConsumer WHERE Name=\"BBBBBB\"" ascii //weight: 1
        $x_1_5 = "PATH __EventFilter WHERE Name=\"AAAAAA\"" ascii //weight: 1
        $x_1_6 = "*HuTaoConfig*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Coinminer_ABTX_2147839135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.ABTX!MTB"
        threat_id = "2147839135"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0a 2b 0e 20 e8 03 00 00 28 ?? ?? ?? 0a 06 17 58 0a 06 7e 06 00 00 04 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Coinminer_WRA_2147896140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.WRA!MTB"
        threat_id = "2147896140"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://checkip.dyndns.org" ascii //weight: 1
        $x_1_2 = "DownloadString" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "StartXMRig" ascii //weight: 1
        $x_1_5 = "P_OutputDataReceived" ascii //weight: 1
        $x_1_6 = "https://api.telegram.org/bot2112414722:AAGuX-HNbrmTUBCQ_UXlO4o-fJHerni8xUw/sendMessage?chat_id=-1001777723555&text=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Coinminer_AIU_2147904180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.AIU!MTB"
        threat_id = "2147904180"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exe.repleh\\ataDmargorP\\:C" wide //weight: 1
        $x_1_2 = "/15.161.701.901//:ptth" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Coinminer_CM_2147942319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinminer.CM!MTB"
        threat_id = "2147942319"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 03 07 58 91 0d 07 17 58 0b 09 20 80 00 00 00 5f 16 fe 01 13 05 11 05 2d 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

