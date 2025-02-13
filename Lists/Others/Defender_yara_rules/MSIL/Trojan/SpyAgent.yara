rule Trojan_MSIL_SpyAgent_PA_2147751989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyAgent.PA!MTB"
        threat_id = "2147751989"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keyloggerpassword" wide //weight: 1
        $x_1_2 = "No Antivirus" wide //weight: 1
        $x_1_3 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr" wide //weight: 1
        $x_1_4 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools" wide //weight: 1
        $x_1_5 = "Welcome to Firebird! Your system is currently being monitored" wide //weight: 1
        $x_1_6 = "screenCapture" ascii //weight: 1
        $x_1_7 = "GrabAllPasswords" ascii //weight: 1
        $x_1_8 = "killprocessbyname" ascii //weight: 1
        $x_1_9 = "ElevateSelfStartup" ascii //weight: 1
        $x_1_10 = "KeylogSubject" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyAgent_MA_2147796704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyAgent.MA!MTB"
        threat_id = "2147796704"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 02 07 6f ?? ?? ?? 0a 03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d1 6f ?? ?? ?? 0a 26 07 17 58 0b 07 02 6f ?? ?? ?? 0a 32 d5 06 6f ?? ?? ?? 0a 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "FromBase64" ascii //weight: 1
        $x_1_3 = "StringDecrypt" ascii //weight: 1
        $x_1_4 = "RequestConnection" ascii //weight: 1
        $x_1_5 = "CreateShadowCopy" ascii //weight: 1
        $x_1_6 = "get_URL" ascii //weight: 1
        $x_1_7 = "get_IP" ascii //weight: 1
        $x_1_8 = "get_Password" ascii //weight: 1
        $x_1_9 = "get_geoplugin_countryCode" ascii //weight: 1
        $x_1_10 = "get_Http" ascii //weight: 1
        $x_1_11 = "get_NameOfBrowser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyAgent_MC_2147808552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyAgent.MC!MTB"
        threat_id = "2147808552"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 09 b9 05 1f 6d 2f 41 94 c5 5c cb eb fb 4e 68 41 38 8d 64 79 2d 3e 3a 38 bc 34 80 c1 e4 85 3a ad 7e 99 1d 5d cd 4c 0e 62 b8 5c b5 1b c3 c8 a7}  //weight: 1, accuracy: High
        $x_1_2 = {0c 08 02 16 02 8e 69 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 06 28 ?? ?? ?? 06 0d 28 ?? ?? ?? 06 09 2a}  //weight: 1, accuracy: Low
        $x_1_3 = "RijndaelManaged" ascii //weight: 1
        $x_1_4 = "CipherMode" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
        $x_1_8 = "Replace" ascii //weight: 1
        $x_1_9 = "StrReverse" ascii //weight: 1
        $x_1_10 = "Virtual" ascii //weight: 1
        $x_1_11 = "Protect" ascii //weight: 1
        $x_1_12 = "FromBase64" ascii //weight: 1
        $x_1_13 = "set_Key" ascii //weight: 1
        $x_1_14 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_15 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyAgent_SP_2147840115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyAgent.SP!MTB"
        threat_id = "2147840115"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 06 07 8e 69 5d 02 06 08 07 28 ?? ?? ?? 06 9c 06 15 58 0a 06 16 fe 04 16 fe 01 13 05 11 05 2d df}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyAgent_SPAZ_2147841673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyAgent.SPAZ!MTB"
        threat_id = "2147841673"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 06 09 06 9a 1f 10 28 ?? ?? ?? 0a 9c 06 17 58 0a 06 09 8e 69 fe 04 13 0b 11 0b 2d e2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyAgent_SB_2147920863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyAgent.SB!MTB"
        threat_id = "2147920863"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 9a 6f 4e 00 00 0a 72 db 07 00 70 28 3b 00 00 0a 2c 64 07 08 9a 6f 50 00 00 0a 0d 09 28 ?? ?? ?? 0a 72 5b 08 00 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyAgent_CCJB_2147921007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyAgent.CCJB!MTB"
        threat_id = "2147921007"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 06 11 0c 9a 6f 4e 00 00 0a 72 ?? ?? 00 70 28 4f 00 00 0a 39 cc 00 00 00 11 06 11 0c 9a 6f 50 00 00 0a 13 0d 11 0d 28 51 00 00 0a 26 11 06 11 0c 9a 6f 52 00 00 0a 13 0e 28 53 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = {13 18 12 18 fe 16 ?? 00 00 01 6f 18 00 00 0a 72 ?? ?? 00 70 72 ?? ?? 00 70 6f 54 00 00 0a 13 0f 11 07 72 ?? ?? 00 70 11 06 11 0c 9a 6f 55 00 00 0a 28 56 00 00 0a 13 10 11 10 73 57 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {13 11 11 11 6f 48 00 00 0a 2d 5d 11 06 11 0c 9a 6f 55 00 00 0a 72 ?? ?? 00 70 28 4f 00 00 0a 2c 47 11 0d 11 07 72 ?? ?? 00 70 11 06 11 0c 9a 6f 55 00 00 0a 28 56 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_4 = {28 58 00 00 0a 09 72 ?? ?? 00 70 28 39 00 00 0a 11 0e 72 ?? ?? 00 70 11 0f 72 ?? ?? 00 70 28 59 00 00 0a 28 5a 00 00 0a 11 0d 28 5b 00 00 0a de 10 13 12 11 12 6f 2f 00 00 0a 28 30 00 00 0a de 00 11 0c 17 58 13 0c 11 0c 11 06 8e 69 3f f8 fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyAgent_NIT_2147922108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyAgent.NIT!MTB"
        threat_id = "2147922108"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 06 02 1f 0a 28 ?? 00 00 06 13 07 28 ?? 00 00 06 72 c0 04 00 70 11 07 6f ?? 00 00 0a 13 08 11 04 11 07 11 06 74 64 00 00 01 28 ?? 00 00 0a 6f ?? 00 00 0a 11 08 72 de 04 00 70 02 1d 28 ?? 00 00 06 11 06 74 64 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 13 08 09 11 08 28 ?? 00 00 0a 0d 11 05 6f ?? 00 00 0a 2d 8d}  //weight: 2, accuracy: Low
        $x_1_2 = "Falcon_Keylogger" ascii //weight: 1
        $x_1_3 = "Send logs interval" wide //weight: 1
        $x_1_4 = "chkUACExploit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyAgent_CA_2147927332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyAgent.CA!MTB"
        threat_id = "2147927332"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IsProxyDetectedUsingWMI" ascii //weight: 1
        $x_1_2 = "CheckForVMHardware" ascii //weight: 1
        $x_1_3 = "DetectSandBoxByDll" ascii //weight: 1
        $x_1_4 = "DetectMonitiringTool" ascii //weight: 1
        $x_1_5 = "CheckForVMProcesses" ascii //weight: 1
        $x_1_6 = "CheckForVPSEnvironment" ascii //weight: 1
        $x_1_7 = "IsProxyDetectedUsingRegistry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

