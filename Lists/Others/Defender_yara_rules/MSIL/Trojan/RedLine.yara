rule Trojan_MSIL_RedLine_2147794376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine!MTB"
        threat_id = "2147794376"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sdi845sa" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RPS_2147797360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RPS!MTB"
        threat_id = "2147797360"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Wallet" ascii //weight: 1
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "SpecialFolder" ascii //weight: 1
        $x_1_4 = "Split" ascii //weight: 1
        $x_1_5 = "FromBase64" ascii //weight: 1
        $x_1_6 = "ScanPasswords" ascii //weight: 1
        $x_1_7 = "CreateNoWindow" ascii //weight: 1
        $x_1_8 = "WaitForExit" ascii //weight: 1
        $x_1_9 = "WebClient" ascii //weight: 1
        $x_1_10 = "DownloadFile" ascii //weight: 1
        $x_1_11 = "Login Data" wide //weight: 1
        $x_1_12 = "Web Data" wide //weight: 1
        $x_1_13 = "Cookies" wide //weight: 1
        $x_1_14 = "Opera" wide //weight: 1
        $x_1_15 = "autofill" wide //weight: 1
        $x_1_16 = "card_number_encrypted" wide //weight: 1
        $x_1_17 = "Telegram" wide //weight: 1
        $x_1_18 = "discord" wide //weight: 1
        $x_1_19 = "FileZilla" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_DS_2147818982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.DS!MTB"
        threat_id = "2147818982"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 28 2a 00 00 0a 2c 08 7e 0a 00 00 0a 0a de 19 02 28 37 00 00 06 03 28 36 00 00 06 28 37 00 00 06 0a de 05 26 02 0a de 00 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MB_2147826871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MB!MTB"
        threat_id = "2147826871"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0b 16 0c 16 0c 2b 3e 03 08 03 8e 69 5d 17 58 17 59 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MB_2147826871_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MB!MTB"
        threat_id = "2147826871"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 1f 20 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 08 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 73 ?? ?? ?? 0a 0d 09 07 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 04 11 04 06 16 06 8e 69 6f ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a de 0f 11 04 2c 0a 1c 2c f9 11 04 6f ?? ?? ?? 0a dc}  //weight: 1, accuracy: Low
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
        $x_1_7 = "ToArray" ascii //weight: 1
        $x_1_8 = "TransformFinalBlock" ascii //weight: 1
        $x_1_9 = "GetTempPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MB_2147826871_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MB!MTB"
        threat_id = "2147826871"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {3a 00 2f 00 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2e 00 73 00 68 00 2f 00 67 00 65 00 74 00 2f 00 [0-15] 2f 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 42 00 79 00 74 00 65 00 73 00 2e 00 74 00 78 00 74 00}  //weight: 5, accuracy: Low
        $x_5_2 = {57 95 02 34 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 34 00 00 00 60 1b 00 00 2b 00 00 00 f7 36 00 00 02 00 00 00 3e 00 00 00 10}  //weight: 5, accuracy: High
        $x_5_3 = "gCyXFCJTPzQpmCXjvWkwkAKjzvtyhKZvezfPvOQrM" wide //weight: 5
        $x_5_4 = "vPBHBKlugaMnPTVucEwJyptkIKCB" wide //weight: 5
        $x_5_5 = "JyzUHWfQCYIpIPJrllxDQLaSivREMJWCXLcWIRcc" wide //weight: 5
        $x_1_6 = "DecodingBytes" ascii //weight: 1
        $x_1_7 = "GetTempPath" ascii //weight: 1
        $x_1_8 = "WinDll.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MC_2147826872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MC!MTB"
        threat_id = "2147826872"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {13 04 12 03 12 00 28 02 00 00 06 74 01 00 00 1b 13 05 11 05 28 04 00 00 0a 13 06 11 04 13 07 28 01 00 00 0a 1f 33 8d 02 00 00 01 25 d0 05 00 00 04}  //weight: 10, accuracy: High
        $x_1_2 = "ConfigurationFileSourceWatcher" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MC_2147826872_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MC!MTB"
        threat_id = "2147826872"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 06 72 01 00 00 70 28 ?? ?? ?? 0a 72 04 02 00 70 6f ?? ?? ?? 0a 1f 64 73 0e 00 00 0a 1f 10 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 46 02 00 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 17 73 11 00 00 0a 0c 08 02 16 02 8e 69 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a de 0a 08 2c 06 08 6f ?? ?? ?? 0a dc 07 6f ?? ?? ?? 0a 0d de 14}  //weight: 1, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MC_2147826872_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MC!MTB"
        threat_id = "2147826872"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "[^\\u0020-\\u007F]UNKNOWN" wide //weight: 5
        $x_5_2 = "Removeg[@name=\\PasswString.Removeord\\" wide //weight: 5
        $x_5_3 = "valuString.RemoveeROOT\\SecurityCenter" wide //weight: 5
        $x_5_4 = "ROOT\\SecurityCenter2Web DataExtension Cookies" wide //weight: 5
        $x_5_5 = "NordVpn.exe*NoGetDirectoriesrd" wide //weight: 5
        $x_2_6 = "NameSELECT * FROM" wide //weight: 2
        $x_2_7 = "Replaceing[@name=\\UString.Replacesername" wide //weight: 2
        $x_2_8 = "String.Replaceluemoz_cookies" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MD_2147827124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MD!MTB"
        threat_id = "2147827124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 02 8e 69 1b 59 8d ?? 00 00 01 0b 02 1b 07 16 02 8e 69 1b 59 28 ?? 00 00 0a 00 07 16 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MD_2147827124_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MD!MTB"
        threat_id = "2147827124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 06 07 16 1a 6f ?? ?? ?? 0a 26 07 16 28 ?? ?? ?? 0a 0c 06 16 73 ?? ?? ?? 0a 0d 08 8d 26 00 00 01 13 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 39 46 00 00 00 26 20 02 00 00 00 38 1d 00 00 00 09 11 04 16 08 28 ?? ?? ?? 06 26 38 26 00 00 00 20 02 00 00 00 fe 0e 06 00 fe}  //weight: 1, accuracy: Low
        $x_1_2 = "MemoryStream" ascii //weight: 1
        $x_1_3 = "Decompress" ascii //weight: 1
        $x_1_4 = "GetTempPath" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "GZipStream" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MD_2147827124_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MD!MTB"
        threat_id = "2147827124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {26 72 21 02 00 70 0b 72 63 02 00 70 72 7f 02 00 70 07 28 8d 00 00 0a 0c 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 17 0d de 05 26 16 0d de}  //weight: 20, accuracy: Low
        $x_2_2 = "://api.ip.sb/ip" wide //weight: 2
        $x_2_3 = "\\Discord\\Local Storage\\leveldb" wide //weight: 2
        $x_2_4 = "\\TeEnvironmentlegraEnvironmentm DEnvironmentesktoEnvironmentp\\tdEnvironmentata" wide //weight: 2
        $x_2_5 = "*wallet*" wide //weight: 2
        $x_2_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" wide //weight: 2
        $x_2_7 = "shell\\open\\command" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_ME_2147827761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.ME!MTB"
        threat_id = "2147827761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0d 16 13 04 2b 22 09 11 04 9a 13 05 06 11 05 6f ?? ?? ?? 06 2c 0c 06 6f ?? ?? ?? 06 2c 04 17 0b 2b 0d 11 04 17 58 13 04 11 04 09 8e 69 32 d7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_ME_2147827761_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.ME!MTB"
        threat_id = "2147827761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 02 16 02 8e 69 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a de 0a 08 2c 06 08 6f ?? ?? ?? 0a dc 07 6f ?? ?? ?? 0a 0d de 14}  //weight: 5, accuracy: Low
        $x_5_2 = {0b 16 0c 2b 78 06 08 9a 16 9a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 2d 11 06 08 9a 16 9a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_ME_2147827761_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.ME!MTB"
        threat_id = "2147827761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 f5 02 3c 09 0f 00 00 00 f0 00 30 00 06 00 00 01 00 00 00 57 00 00 00 53 00 00 00 8a 00 00 00 e3 00 00 00 1b}  //weight: 10, accuracy: High
        $x_1_2 = "GetTempPath" ascii //weight: 1
        $x_1_3 = "get_ExecutablePath" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "TransformFinalBlock" ascii //weight: 1
        $x_1_8 = "fdsffffdffsdf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MF_2147828807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MF!MTB"
        threat_id = "2147828807"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 04 08 11 04 9a 1f 10 28 ?? ?? ?? 0a 9c 11 04 17 d6 13 04 00 11 04 20 ?? ?? ?? 00 fe 04 13 06 11 06 2d db 09 13 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MF_2147828807_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MF!MTB"
        threat_id = "2147828807"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 02 16 03 8e 69 6f ?? 00 00 0a 0d 09 13 04 2b 00 11 04 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MF_2147828807_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MF!MTB"
        threat_id = "2147828807"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 02 16 02 8e 69 28 ?? ?? ?? 06 2a 73 53 00 00 0a 38 62 ff ff ff 0a 38 61 ff ff ff 0b 38 67 ff ff ff 73 54 00 00 0a 38 67 ff ff ff 28 ?? ?? ?? 06 38 6c ff ff ff 03 38 6b ff ff ff 28 ?? ?? ?? 06 38 66 ff ff ff 28 ?? ?? ?? 06 38 61 ff ff ff 0c 38 60 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = "get_ExecutablePath" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "Replace" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "TransformFinalBlock" ascii //weight: 1
        $x_1_8 = "fdsffffdffsdf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MI_2147828810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MI!MTB"
        threat_id = "2147828810"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 03 16 03 8e 69 28 9b 01 00 06 2a 0a 38 65 ff ff ff 0b 38 6d ff ff ff 0c 2b 92}  //weight: 5, accuracy: High
        $x_5_2 = {57 dd a2 2b 09 0f 00 00 00 d8 00 23 00 06 00 00 01 00 00 00 84 00 00 00 92 00 00 00 72 01 00 00 c6}  //weight: 5, accuracy: High
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MI_2147828810_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MI!MTB"
        threat_id = "2147828810"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 d5 02 fc 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 3d 00 00 00 11 00 00 00 34}  //weight: 10, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "HttpWebRequest" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "set_UserAgent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MI_2147828810_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MI!MTB"
        threat_id = "2147828810"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Hacek.exe" wide //weight: 5
        $x_1_2 = "GatewayIPAddressInformationCollection" ascii //weight: 1
        $x_1_3 = "GetDefaultIPv4Address" ascii //weight: 1
        $x_1_4 = "Capture" ascii //weight: 1
        $x_1_5 = "BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_ML_2147828813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.ML!MTB"
        threat_id = "2147828813"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 8e 69 8d ?? ?? ?? 01 13 02 38 ?? ?? ?? ?? 11 02 11 03 11 01 11 03 11 01 8e 69 5d 91 11 04 11 03 91 61 d2 9c 20 ?? ?? ?? ?? 7e ?? ?? ?? 04 7b ?? ?? ?? 04 39 ?? ?? ?? ff}  //weight: 10, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "DynamicInvoke" ascii //weight: 1
        $x_1_4 = "GetResponse" ascii //weight: 1
        $x_1_5 = "LoginUtils" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MM_2147828814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MM!MTB"
        threat_id = "2147828814"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 d5 a2 2b 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 6e 00 00 00 77}  //weight: 10, accuracy: High
        $x_1_2 = "SkipVerification" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
        $x_1_6 = "IsLittleEndian" ascii //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MQ_2147829578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MQ!MTB"
        threat_id = "2147829578"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 fd a2 35 09 00 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 39 00 00 00 28 00 00 00 6c 00 00 00 65 00 00 00 3d}  //weight: 10, accuracy: High
        $x_1_2 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_3 = "Sleep" ascii //weight: 1
        $x_1_4 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_5 = "CrtImplementationDetails" ascii //weight: 1
        $x_1_6 = "DefaultDomain.DoNothing" ascii //weight: 1
        $x_1_7 = "cookie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MS_2147829581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MS!MTB"
        threat_id = "2147829581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 fd a2 35 09 00 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 39 00 00 00 26 00 00 00 49 00 00 00 6b}  //weight: 10, accuracy: High
        $x_1_2 = "SecurityAction" ascii //weight: 1
        $x_1_3 = "IsUpper<char>" ascii //weight: 1
        $x_1_4 = "cookie" ascii //weight: 1
        $x_1_5 = "SkipVerification" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MR_2147830103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MR!MTB"
        threat_id = "2147830103"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 fd a2 35 09 00 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 39 00 00 00 27 00 00 00 4a 00 00 00 65}  //weight: 10, accuracy: High
        $x_1_2 = "cookie" ascii //weight: 1
        $x_1_3 = "CrtImplementationDetails" ascii //weight: 1
        $x_1_4 = "DomainUnload" ascii //weight: 1
        $x_1_5 = "SkipVerification" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_2147830104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MT!MTB"
        threat_id = "2147830104"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 15 a2 09 09 0b 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 35 00 00 00 0c 00 00 00 12 00 00 00 31}  //weight: 1, accuracy: High
        $x_1_2 = "92ad98ed-8c3b-4ccb-94f9-c50da764d548" ascii //weight: 1
        $x_1_3 = "Jambo" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "PervasiveMindChallenge.Properties" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "TransformFinalBlock" ascii //weight: 1
        $x_1_8 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MU_2147830389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MU!MTB"
        threat_id = "2147830389"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 0c 06 72 7b 07 00 70 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 07 17 58 0b 07 02 6f ?? ?? ?? 0a 32 ca}  //weight: 10, accuracy: Low
        $x_1_2 = "nameExtension Cookies" wide //weight: 1
        $x_1_3 = "host_keyAppData\\Local\\" wide //weight: 1
        $x_1_4 = "encrypted_value" wide //weight: 1
        $x_1_5 = "AppData\\Local\\Yandex\\YandexBrowser\\User Data" wide //weight: 1
        $x_1_6 = "AppData\\Local\\360Browser\\Browser\\User Data" wide //weight: 1
        $x_1_7 = "SkipVerification" ascii //weight: 1
        $x_1_8 = "Decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MV_2147830390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MV!MTB"
        threat_id = "2147830390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 16 06 8e 69 6f ?? ?? ?? 0a 0d 09 8e 69 1f 10 59 8d ?? ?? ?? 01 13 04 09 1f 10 11 04 16 09 8e 69 1f 10 59 28 ?? ?? ?? 0a 00 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 17 9a 80 ?? ?? ?? 04 02 13 05 2b 00 11 05 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "UserControl" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MW_2147830394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MW!MTB"
        threat_id = "2147830394"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 1a 58 11 04 16 08 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 7e ?? ?? ?? 04 11 05 6f a9 00 00 0a 7e ?? ?? ?? 04 02 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 17 59 28 ?? ?? ?? 0a 16 7e ?? ?? ?? 04 02 1a 28 ?? ?? ?? 0a 11 05 0d}  //weight: 10, accuracy: Low
        $x_6_2 = {57 ff a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 dc 00 00 00 89 00 00 00 4f 01 00 00 3e 02 00 00 b5 02}  //weight: 6, accuracy: High
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "TransformBlock" ascii //weight: 1
        $x_1_5 = "FromBase64CharArray" ascii //weight: 1
        $x_1_6 = "ClientCredentials" ascii //weight: 1
        $x_1_7 = "GetDecoded" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MH_2147831538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MH!MTB"
        threat_id = "2147831538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 09 11 03 16 11 03 8e 69 6f ?? ?? ?? 0a 13 06 38 ?? ?? ?? ?? 14 13 06 20 01 00 00 00 28 ?? ?? ?? 06 3a ?? ?? ?? ?? 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MH_2147831538_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MH!MTB"
        threat_id = "2147831538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 07 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08}  //weight: 5, accuracy: Low
        $x_2_2 = "98a42a15-c16e-45ce-b4bc-c05d04e82f1f" ascii //weight: 2
        $x_2_3 = "Minesweeper_Windows.Properties" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MH_2147831538_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MH!MTB"
        threat_id = "2147831538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 fd a2 3d 09 0f 00 00 00 f8 00 31 00 06 00 00 01 00 00 00 5d}  //weight: 10, accuracy: High
        $x_1_2 = "MemberRefsProxy" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
        $x_1_6 = "GetTempPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_NFA_2147831734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.NFA!MTB"
        threat_id = "2147831734"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f ?? 00 00 0a 08 17 58 0c 08 02 8e 69}  //weight: 1, accuracy: Low
        $x_1_2 = "6f2fa8b7-cca1-41ca-a1b4-541146e4c16f" ascii //weight: 1
        $x_1_3 = {20 80 f0 fa 02 6f ?? 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_4 = "GetTempPath" ascii //weight: 1
        $x_1_5 = "megalinkbj" ascii //weight: 1
        $x_1_6 = "Oakcdq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_NFK_2147831790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.NFK!MTB"
        threat_id = "2147831790"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 ff a2 3f 09 1e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 11 01 00 00 95 00 00 00 8b 01 00 00 07}  //weight: 2, accuracy: High
        $x_2_2 = "kasdihbfpfduqw" ascii //weight: 2
        $x_2_3 = "5K Player" ascii //weight: 2
        $x_2_4 = "XRails.Classses" ascii //weight: 2
        $x_1_5 = "NativeMethods" ascii //weight: 1
        $x_1_6 = "get_encrypted_key" ascii //weight: 1
        $x_1_7 = "FromBase64CharArray" ascii //weight: 1
        $x_1_8 = "BitConverter" ascii //weight: 1
        $x_1_9 = "Reverse" ascii //weight: 1
        $x_1_10 = "ConfusedByAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MX_2147831916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MX!MTB"
        threat_id = "2147831916"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 09 06 06 da 17 d6 2e 07 72 53 00 00 70 2b 05 72 2d 06 00 70 6f ?? ?? ?? 0a 00 7e b8 00 00 04 09 17 d6 09 06 06 da 17 d6 2e 07 72 53 00 00 70 2b 05 72 35 06 00 70 6f ?? ?? ?? 0a 00 7e b8 00 00 04 09 18 d6 09 06 06 da 17 d6 2e 07 72 53 00 00 70 2b 05}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "ConnectionState" ascii //weight: 1
        $x_1_4 = "frmFeePaymentReceipt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MY_2147831917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MY!MTB"
        threat_id = "2147831917"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 07 0c 16 0d 38 39 00 00 00 08 09 a3 0c 00 00 01 13 04 11 04 28 ?? ?? ?? 0a 23 00 00 00 00 00 80 73 40 59 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 69 13 05 06 11 05 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 09 17 58 0d 09 08 8e 69 32 c1}  //weight: 5, accuracy: Low
        $x_1_2 = "DownloadString" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_5_4 = "://81.161.229.110/" wide //weight: 5
        $x_1_5 = "InvokeMember" ascii //weight: 1
        $x_1_6 = "get_Location" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDB_2147833127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDB!MTB"
        threat_id = "2147833127"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 19 04 5a 61 d1 2a}  //weight: 2, accuracy: High
        $x_2_2 = {03 04 61 d1 2a}  //weight: 2, accuracy: High
        $x_2_3 = {03 18 61 d1 2a}  //weight: 2, accuracy: High
        $x_2_4 = {2a 56 02 7b ?? ?? ?? ?? 04 02 7b ?? ?? ?? ?? 8e 69 5d 93 03 61 d2 2a}  //weight: 2, accuracy: Low
        $x_2_5 = {8c 38 00 00 01 07 18 28 0e 00 00 2b 28 6e 00 00 0a 13 07 11 07 08 18 28 0e 00 00 2b 28 6e 00 00 0a 13 07 11 07 09 18 17 8d 0b 00 00 01 25 16 11 06 a2 28 6e 00 00 0a 13 07 11 07 11 04 18 28 0e 00 00 2b 28 6e 00 00 0a 13 07 11 07 11 05 17 18 8d 0b 00 00 01 25 16 16 8c 38 00 00 01 a2 28 6e 00 00 0a 13 07 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_ABA_2147834217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.ABA!MTB"
        threat_id = "2147834217"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {a2 25 17 20 00 01 00 00 8c ?? ?? ?? 01 a2 25 1a 16 8d ?? ?? ?? 01 a2 14 14 14 17 28}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_NZD_2147835801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.NZD!MTB"
        threat_id = "2147835801"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 66 73 64 73 73 73 73 73 73 [0-2] 68 64 68 66 64 66 6b 67}  //weight: 3, accuracy: Low
        $x_3_2 = "jddssssssssssssssssssssssf" ascii //weight: 3
        $x_3_3 = "fffffdhfkffdgj" ascii //weight: 3
        $x_3_4 = "jhffsd" ascii //weight: 3
        $x_1_5 = "RijndaelManaged" ascii //weight: 1
        $x_1_6 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_ABB_2147835846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.ABB!MTB"
        threat_id = "2147835846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 8e 69 5d 7e ?? ?? ?? 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 03 08 17 58 03 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a 31}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MP_2147835918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MP!MTB"
        threat_id = "2147835918"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 28 c3 00 00 06 03 28 c2 00 00 06 28 c3 00 00 06 0a de 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MP_2147835918_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MP!MTB"
        threat_id = "2147835918"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "78fc2139-3c2c-4527-8c46-b1b94ca0a58a" ascii //weight: 1
        $x_1_2 = "Shitz" ascii //weight: 1
        $x_1_3 = "Klassen.Properties.Resources" ascii //weight: 1
        $x_1_4 = "Jambo" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_NZQ_2147836546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.NZQ!MTB"
        threat_id = "2147836546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 91 07 08 07 8e 69 5d 91 61 28 dc 00 00 06 03 08 18 58 17 59 03 8e 69 5d 91 59 20 fa 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 00 00 13 66 00 73 00 64 00 66 00 66 00 64 00 66 00 20 00 66 00 00 0b 32 00 32 00 32 00 32 00 41}  //weight: 1, accuracy: High
        $x_1_3 = "fdsffffdffsdf" ascii //weight: 1
        $x_1_4 = "adsssssssssssa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_NZS_2147837417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.NZS!MTB"
        threat_id = "2147837417"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 02 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 7e 1a 00 00 04 02 91 61 d2 0a 2b 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "JJ4VWQDRSD3U5YV" ascii //weight: 1
        $x_1_3 = "PORTRAY.e" ascii //weight: 1
        $x_1_4 = "COLLEAGUE_TP.P" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_NZV_2147837418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.NZV!MTB"
        threat_id = "2147837418"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 00 08 20 00 04 00 00 58 28 ?? 00 00 2b 07 02 08 20 00 04 00 00 6f ?? 00 00 0a 0d 08 09 58 0c 09 20 00 04 00 00 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "ghgbevny.tln" ascii //weight: 1
        $x_1_3 = "rzcgl" ascii //weight: 1
        $x_1_4 = "WWQWQW" ascii //weight: 1
        $x_1_5 = "GZipStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDI_2147837540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDI!MTB"
        threat_id = "2147837540"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fe 09 04 00 fe 09 05 00 60 fe 09 04 00 66 fe 09 05 00 66 60 5f fe 0e 00 00 fe 09 03 00 fe 0c 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "R3f3r3nc3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDJ_2147837541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDJ!MTB"
        threat_id = "2147837541"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Nokia Desktop Client" ascii //weight: 1
        $x_1_2 = "LoadLibrary" ascii //weight: 1
        $x_1_3 = "GetProcAddress" ascii //weight: 1
        $x_1_4 = "GetSystemMetrics" ascii //weight: 1
        $x_1_5 = "user32" ascii //weight: 1
        $x_1_6 = "kernel32" ascii //weight: 1
        $x_2_7 = {06 07 06 07 93 20 7e 00 00 00 61 02 61 d1 9d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_NZY_2147837578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.NZY!MTB"
        threat_id = "2147837578"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jddssssssssssssssfsssssssffsddhfhkfj" ascii //weight: 1
        $x_1_2 = "sddddffshdjfffffgjskdgsacsafp" ascii //weight: 1
        $x_1_3 = "jcfsfdsafsdgkffff" ascii //weight: 1
        $x_1_4 = "fhddsffhss" ascii //weight: 1
        $x_1_5 = "FromBase64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MBAR_2147838800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MBAR!MTB"
        threat_id = "2147838800"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 6c 6b 46 53 6f 64 64 62 65 2e 65 78 65 00 6a 6c 6b 46 53 6f 64 64 62 65 00 3c}  //weight: 2, accuracy: High
        $x_2_2 = "fdfffjffsffagfcfdssfkfhgj" ascii //weight: 2
        $x_2_3 = "hdssdgfdfkshfffdj" ascii //weight: 2
        $x_2_4 = "sfhjfkfhfjsfhdhfffffafdsfgfssscfgdb" ascii //weight: 2
        $x_1_5 = "RijndaelManaged" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MBAS_2147838861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MBAS!MTB"
        threat_id = "2147838861"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 16 07 0c 08 14 72 48 40 02 70 16 8d}  //weight: 1, accuracy: High
        $x_1_2 = {34 00 44 00 2d 00 35 00 41 00 2d 00 39 00 5b 00 7e 00 2d 00 5b 00 33 00 7e 00 7e 00 7e 00 2d 00 5b 00 34 00 7e 00 7e 00 7e 00 2d 00 46 00 46 00 2d 00 46 00 46 00 7e 00 7e 00 2d 00 42 00 38 00 7e}  //weight: 1, accuracy: High
        $x_1_3 = "LLLL56" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDL_2147838980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDL!MTB"
        threat_id = "2147838980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "319d5a82-58fe-4cf6-b8c6-e2158468194f" ascii //weight: 1
        $x_1_2 = "XPdriver" ascii //weight: 1
        $x_1_3 = "PfrWYnnGIxPiVj8thV.oVUVap9rcGKKDmpRJP" wide //weight: 1
        $x_1_4 = "d8ZHEHAGyrJ62n0N4d" ascii //weight: 1
        $x_1_5 = "YOk0KMybFf6WVr1a8R" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MKV_2147839386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MKV!MTB"
        threat_id = "2147839386"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 11 04 06 8e 69 5d 06 11 04 06 8e 69 5d 91 07 11 04 1f 16 5d 91 61 28 ?? ?? ?? 0a 06 11 04 17 58 06 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 ?? ?? ?? 00 58 20 00 01 00 00 5d d2 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d b0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_NG_2147839770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.NG!MTB"
        threat_id = "2147839770"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0c 00 00 28 ?? 00 00 0a 28 ?? 00 00 0a 25 7e ?? 00 00 04 61 20 ?? 00 00 00 59 20 ?? 00 00 00 fe ?? ?? 00 5a 58 fe ?? ?? 00}  //weight: 5, accuracy: Low
        $x_1_2 = "animation.RenderNodeAnimator.module12" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDP_2147840150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDP!MTB"
        threat_id = "2147840150"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "epIIFrFphrnog" ascii //weight: 1
        $x_1_2 = "b0b6aae8-9c7d-4683-aaf8-3429bb5ed8e6" ascii //weight: 1
        $x_1_3 = "Qkkbal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_NRL_2147840342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.NRL!MTB"
        threat_id = "2147840342"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 c9 02 00 06 0a 28 ?? ?? 00 06 0b 07 1f 20 8d ?? ?? 00 01 25 d0 ?? ?? 00 04 28 ?? ?? 00 0a 6f ?? ?? 00 0a 07 1f 10 8d ?? ?? 00 01 25 d0 ?? ?? 00 04 28 ?? ?? 00 0a 6f ?? ?? 00 0a 06 07 6f ?? ?? 00 0a 17 73 ?? ?? 00 0a 25 02 16 02 8e 69 6f ?? ?? 00 0a 6f ?? ?? 00 0a 06 28 ?? ?? 00 06 28 ?? ?? 00 06 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "Sacredly.g.resources" ascii //weight: 1
        $x_1_3 = "FromBase64CharArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDQ_2147840520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDQ!MTB"
        threat_id = "2147840520"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Coye_Th0ms0lv0s" ascii //weight: 1
        $x_1_2 = "Coye_An7wer" ascii //weight: 1
        $x_1_3 = "Coye_5ound" ascii //weight: 1
        $x_1_4 = "Coye_2ystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDT_2147840610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDT!MTB"
        threat_id = "2147840610"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0c1db332-7b29-4cff-a194-bdb5fb6a6057" ascii //weight: 1
        $x_1_2 = "file_type_pdf_icon_130274.ico" ascii //weight: 1
        $x_1_3 = {92 00 33 00 6c 00 65 00 36 00 8e 00 8d 00 31 00 8e 00 65 00 8a 00 75 00 6e 00 8f 00 62 00 73 00 71 00 8f 00 2e 00 72 00 8b 00 95 00 8b 00 70 00 87 00 8e 00 98 00 94 00 73 00 90 00 6d 00 90 00 96 00 9c 00 39 00 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 00 71 00 8e 00 89 00 62 00 87 00 9f 00 92 00 79 00 9c 00 87 00 66 00 8c 00 88 00 73 00 39 00 36 00 2e 00 63 00 69 00 89 00 64 00 97 00 93 00 88 00 73 00 61 00 34 00 8d 00 76 00 72 00 95 00 64 00 9a 00 6e 00 34 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_CPC_2147840682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.CPC!MTB"
        threat_id = "2147840682"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 28 88 00 00 06 03 28 87 00 00 06 28 88 00 00 06 0a de}  //weight: 5, accuracy: High
        $x_5_2 = {7e 02 00 00 04 7e 05 00 00 04 28 8a 00 00 06 17 8d 5c 00 00 01 25 16 1f 7c 9d 6f c2 00 00 0a 0d 16 13 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDV_2147840711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDV!MTB"
        threat_id = "2147840711"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "j3AmrhgkCleVTGdEwA" ascii //weight: 1
        $x_1_2 = "tcartnoCcnysAtsurTSWIytiruceSledoMecivreSmetsyS36749" ascii //weight: 1
        $x_1_3 = {74 00 9c 00 38 00 30 00 91 00 91 00 6e 00 35 00 68 00 8e 00 95 00 62 00 86 00 86 00 8c 00 77 00 2e 00 96 00 89 00 9d 00 72 00 8b 00 6f 00 92 00 77 00 9f 00 8a 00 6b 00 66 00 64 00 6e 00 96 00 64 00 9c 00 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_NRC_2147840802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.NRC!MTB"
        threat_id = "2147840802"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 42 00 00 06 13 08 11 14 20 ?? ?? ?? 5d 5a 20 ?? ?? ?? 7a 61 38 ?? ?? ?? ff 23 ?? ?? ?? ?? ?? ?? ?? 40 23 ?? ?? ?? ?? ?? ?? ?? 40 28 ?? ?? ?? 06 58 28 ?? ?? ?? 06 8d ?? ?? ?? 01 25 16 13 0f 1f fc 20 ?? ?? ?? 17 20 ?? ?? ?? 63 61 20 ?? ?? ?? 74 33 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "NtWriteVirtualMemory" ascii //weight: 1
        $x_1_3 = "Pro0ince" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDW_2147840805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDW!MTB"
        threat_id = "2147840805"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Renumbered" wide //weight: 1
        $x_1_2 = "Microsoft Company Operating System" ascii //weight: 1
        $x_1_3 = "Microsoft Contract Importer/Exporter" ascii //weight: 1
        $x_1_4 = "edocpOpOoNrehctapsiDledoMecivreSmetsyS99319" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDY_2147840806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDY!MTB"
        threat_id = "2147840806"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0c1db332-7b29-4cff-a194-bdb5fb6a6057" ascii //weight: 1
        $x_1_2 = "7039_exe_hardware_hospital_install_installer_icon" ascii //weight: 1
        $x_1_3 = "k6XZrWIoyArWXQpDQo.DfB7Sn25r7hNp4EBKW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDAB_2147841237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDAB!MTB"
        threat_id = "2147841237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rcrjpeomgkmmb" ascii //weight: 1
        $x_2_2 = {26 17 58 7d c3 00 00 04 07 03 1e 63 d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDAD_2147841240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDAD!MTB"
        threat_id = "2147841240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ikmmhrmckAifr" ascii //weight: 1
        $x_2_2 = {03 08 03 8e 69 5d 7e ?? ?? ?? ?? 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? ?? 03 08 19 58 18 59 03 8e 69 5d 91 59 20 03 01 00 00 58 18 59 17 59 20 00 01 00 00 5d d2 9c 08 17 58 1a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDAE_2147841241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDAE!MTB"
        threat_id = "2147841241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fe 0c 00 00 fe 0c 01 00 fe 0c 00 00 fe 0c 01 00 93 20 9a 00 00 00 65 66 61 fe 09 00 00 61 d1 9d}  //weight: 2, accuracy: High
        $x_1_2 = "vDFqUJ5IZf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDAF_2147841242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDAF!MTB"
        threat_id = "2147841242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "lkdmeekankdIk" ascii //weight: 1
        $x_2_2 = {5d 91 61 28 ?? ?? ?? ?? 02 06 1a 58 4a 1d 58 1c 59 02 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_DAM_2147841514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.DAM!MTB"
        threat_id = "2147841514"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0d 16 13 04 2b 1e 09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? 00 00 0a 11 04 13 05 11 05 17 58 13 04 11 04 07 8e 69 32 db}  //weight: 4, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDAN_2147841610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDAN!MTB"
        threat_id = "2147841610"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rapport" ascii //weight: 1
        $x_1_2 = "IOOOIOOPOOPPUPPPYPUOOUIYOPIUUUUYYYOYPYPYIPOPYIPYIUU" ascii //weight: 1
        $x_1_3 = "UIIUYUOOYPPPYYUYUYYI" ascii //weight: 1
        $x_1_4 = "PIOYPUPPIYOYUUIPOPYUIYUOUUYPOYYIYU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDAO_2147841611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDAO!MTB"
        threat_id = "2147841611"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fe 0e 29 00 fe 0c 29 00 fe 0c 2a 00 58 fe 0e 29 00 fe 0c 29 00 fe 0c 29 00 19 62 61 fe 0e 29 00 fe 0c 29 00 fe 0c 2b 00 58 fe 0e 29 00 fe 0c 2a 00 1f 13 62 fe 0c 27 00 59 fe 0c 2a 00 61 fe 0c 29 00 58 fe 0e 29 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDAI_2147841628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDAI!MTB"
        threat_id = "2147841628"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AdkpbIgighIII" ascii //weight: 1
        $x_1_2 = "rh7KLMiasvA=" wide //weight: 1
        $x_1_3 = "qv3klfg3Oxk=" wide //weight: 1
        $x_1_4 = "BUZLUlQ6+QTjPQPxbVO81gIMOaP2weOh" wide //weight: 1
        $x_1_5 = "bxpSqrPee5XMxSQtMqEPjA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDAJ_2147841629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDAJ!MTB"
        threat_id = "2147841629"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "f9ded791-234d-40e9-8d65-c3a8b7963306" ascii //weight: 1
        $x_1_2 = "SafeHandleZeroOrMinusnvalid" ascii //weight: 1
        $x_1_3 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDAP_2147841915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDAP!MTB"
        threat_id = "2147841915"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "9f35ffe8-31e7-4982-98e5-96ca4cc50fb8" ascii //weight: 1
        $x_1_2 = "Tsnqgdjkce" ascii //weight: 1
        $x_1_3 = "Anmxqbnpjn" wide //weight: 1
        $x_1_4 = "Anmxqbnpjn.Skbeafir" wide //weight: 1
        $x_1_5 = "Piwxbrfdbeabfnzbk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDAR_2147842203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDAR!MTB"
        threat_id = "2147842203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2960d20d-bf3d-496b-b7b8-4c105367a7a1" ascii //weight: 1
        $x_1_2 = "Wilcox" ascii //weight: 1
        $x_1_3 = "4D+5A+9}:+}3:::+}4" wide //weight: 1
        $x_1_4 = "73+2}+7}+72+6F+67+72+61+6D+2}+63" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MBBZ_2147842405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MBBZ!MTB"
        threat_id = "2147842405"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 06 18 28 ?? ?? ?? 06 7e ?? 01 00 04 06 28 ?? 01 00 06 0d 7e ?? 01 00 04 09 02 16 02 8e 69 28 ?? 01 00 06 2a 73 97 00 00 0a 38 62 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = "nnoSkdfkecrjc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_EAC_2147842559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.EAC!MTB"
        threat_id = "2147842559"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 0d 18 8d ?? 00 00 01 13 04 11 04 16 28 ?? 00 00 0a a2 11 04 17 09 28 ?? 00 00 0a a2 11 04 13 05 08 28 ?? 00 00 0a 28 ?? 00 00 0a 72 ?? ?? ?? 70 6f ?? 00 00 0a 72 ?? ?? ?? 70 20 00 01 00 00 14 14 11 05 74 ?? 00 00 1b 6f}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "BOojTXAEwwpKmDyZp16v93bOTIEQyBAPriwf99MtqitlmBn0MwpDStedZlMMrn7" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDAV_2147843064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDAV!MTB"
        threat_id = "2147843064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d1cc2bad-d6f7-47b8-afa8-3a9d4430dcc1" ascii //weight: 1
        $x_1_2 = "Discord" ascii //weight: 1
        $x_2_3 = {11 10 1f 0f 5f 11 0d 11 10 1f 0f 5f 95 11 06 25 1a 58 13 06 4b 61}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDAX_2147843727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDAX!MTB"
        threat_id = "2147843727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ed49ca82-72a3-4a33-ad05-c93f24b9918b" ascii //weight: 1
        $x_2_2 = {91 61 d2 9c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6f 94 00 00 0a 17 59 fe 01 0b 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDBC_2147844307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDBC!MTB"
        threat_id = "2147844307"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdb6d273-c699-4148-a48e-6a98a6b16d60" ascii //weight: 1
        $x_1_2 = "KC Softwares" ascii //weight: 1
        $x_1_3 = "professional-setup_full" ascii //weight: 1
        $x_1_4 = "KqmuaSHTUMgkDMYnEqciMjiOJtCQ.JQvpItWKUeplmhsdArwlHtboQalH" ascii //weight: 1
        $x_1_5 = "TextFile1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDBE_2147844561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDBE!MTB"
        threat_id = "2147844561"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXkDb" ascii //weight: 1
        $x_1_2 = "01rti" ascii //weight: 1
        $x_1_3 = "00mVP" ascii //weight: 1
        $x_1_4 = "NG/YqMpi5MZm4L" wide //weight: 1
        $x_1_5 = "Oq+2nEnd6U" wide //weight: 1
        $x_1_6 = "5r2DBHvesB52K9955Y=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MJ_2147844581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MJ!MTB"
        threat_id = "2147844581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 dd 02 fc 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 3b 00 00 00 83}  //weight: 10, accuracy: High
        $x_1_2 = "$$method0x60004e1-21" ascii //weight: 1
        $x_1_3 = "ThreadWasSuspended" ascii //weight: 1
        $x_1_4 = "PasswordExpired" ascii //weight: 1
        $x_1_5 = "IsLogging" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MJ_2147844581_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MJ!MTB"
        threat_id = "2147844581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ConsoleCancel.g.resources" ascii //weight: 1
        $x_1_2 = "ConsoleKeyInfo.Crypto.Form1" ascii //weight: 1
        $x_1_3 = "e4a9333d-1a89-4ab7-8679-424207a3c24a" ascii //weight: 1
        $x_1_4 = "ConsoleCancel.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_EAP_2147844717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.EAP!MTB"
        threat_id = "2147844717"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8e 69 fe 04 fe ?? 06 00 20 50 00 00 00 fe ?? 08 00 00 fe ?? 08 00 20 04 00 00 00 fe 01 39 ?? 00 00 00 fe 09 00 00 73 ?? 00 00 0a 7d ?? 00 00 04 20 05 00 00 00 fe ?? 08 00 00 fe ?? 08 00 20 4d 00 00 00 fe 01 39 ?? 00 00 00 fe 0c 02 00 fe 0c 05 00 fe 0c 01 00 fe 0c 05 00 9a 20 10 00 00 00 28 ?? 00 00 0a d2 9c 20}  //weight: 3, accuracy: Low
        $x_2_2 = "WinControls.PDOControls.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_EAS_2147844725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.EAS!MTB"
        threat_id = "2147844725"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 03 13 07 38 ?? 00 00 00 11 03 11 08 18 5b 11 01 11 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 ?? ff ff ff 26 20 00 00 00 00 38 ?? ff ff ff 16 13 08 38 ?? ff ff ff 11 08 18 58 13 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MBDD_2147844937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MBDD!MTB"
        threat_id = "2147844937"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 2d 9d 6f ?? 00 00 0a 0b 07 8e 69 8d ?? 00 00 01 0d 16 0a 2b 12 09 06 07 06 9a 1f 10 28 ?? 00 00 0a d2 9c 06 17 58 0a 06 07 8e 69 fe 04 13 06 11 06 2d e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDBK_2147845158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDBK!MTB"
        threat_id = "2147845158"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6fc70aba-12f1-4f82-9226-bc3451606b13" ascii //weight: 1
        $x_1_2 = "BlackHatToolz.com 2019" wide //weight: 1
        $x_1_3 = "Pinterest Board Manager" wide //weight: 1
        $x_1_4 = "rcKEG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_SPRT_2147845546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.SPRT!MTB"
        threat_id = "2147845546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {fe 0c 01 00 fe 09 00 00 fe 0c 03 00 6f ?? ?? ?? 0a fe 0c 00 00 fe 0c 03 00 fe 0c 00 00 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d1 fe 0e 05 00 fe 0d 05 00 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a fe 0e 01 00 20 00 00 00 00 fe 0e 06 00 38 18 00 00 00}  //weight: 3, accuracy: Low
        $x_1_2 = "get__votDgy0QeYkTr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDBM_2147845693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDBM!MTB"
        threat_id = "2147845693"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2b76b686-9c5a-4f41-94b3-119c9e5a8d12" ascii //weight: 1
        $x_1_2 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd" ascii //weight: 1
        $x_1_3 = "ECERhANm7l8vGHOtBX.0EBilDYPtu4yaDR1b6" ascii //weight: 1
        $x_1_4 = "SPotCz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDBN_2147845695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDBN!MTB"
        threat_id = "2147845695"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RPnAhBzQnvxpACmaqesnvTusraAHdVijBmwPrVCgXIlNst_IZ" ascii //weight: 1
        $x_1_2 = "QRdvwFTpbItsIFYysxOmxNfTQtARKwwGtlG_FjQsOj" ascii //weight: 1
        $x_1_3 = "sufficient" ascii //weight: 1
        $x_1_4 = "pBEblIrDfRwyMf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDBO_2147845701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDBO!MTB"
        threat_id = "2147845701"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d8d1b4fa-2afb-4d5f-b71e-95f33d209eb6" ascii //weight: 1
        $x_1_2 = "Ddmhxfu" ascii //weight: 1
        $x_1_3 = "//transfer.sh/get/HLC0t8/Phyemrfj.png" wide //weight: 1
        $x_1_4 = "Ecooglraccrghrqdra" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_EM_2147845755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.EM!MTB"
        threat_id = "2147845755"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {25 16 1f 7c 9d 6f d7 00 00 0a 0d 16 13 04 2b 22 09 11 04 9a 13 05 06 11 05 6f 60 00 00 06 2c 0c 06 6f 5d 00 00 06 2c 04 17 0b 2b 0d 11 04 17 58 13 04 11 04 09 8e 69 32 d7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_EM_2147845755_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.EM!MTB"
        threat_id = "2147845755"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dnlibDotNetLinkedResourcev" ascii //weight: 1
        $x_1_2 = "net.tcp://" ascii //weight: 1
        $x_1_3 = "localhost" ascii //weight: 1
        $x_1_4 = "Authorization" ascii //weight: 1
        $x_1_5 = "ChUMByU1KBcJOyZCJgs4UwsFKkcnJQ4a" ascii //weight: 1
        $x_1_6 = "JigpCzA2Hl8=" ascii //weight: 1
        $x_1_7 = "Doorjamb" ascii //weight: 1
        $x_1_8 = "Hydatids.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MBCB_2147845786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MBCB!MTB"
        threat_id = "2147845786"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0d 09 28 ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 11 05 11 04 6f ?? 00 00 0a 11 05 18 6f ?? 00 00 0a 11 05 18 6f 7f 00 00 0a 11 05 6f ?? 00 00 0a 13 06 11 06 07 16 07 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MBCA_2147846039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MBCA!MTB"
        threat_id = "2147846039"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 0b 2b 34 02 07 6f ?? 00 00 0a 03 07 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 0c 06}  //weight: 1, accuracy: Low
        $x_1_2 = {25 16 1f 7c 9d 6f d7 00 00 0a 0d 16 13 04 2b 22 09 11 04 9a 13 05 06 11 05 6f 60 00 00 06 2c 0c 06 6f 5d 00 00 06 2c 04 17 0b 2b 0d 11 04 17 58 13 04 11 04 09 8e 69 32 d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MBCG_2147846042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MBCG!MTB"
        threat_id = "2147846042"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0d 1a 2c 5e 09 28 ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 11 05 11 04 6f ?? 00 00 0a 11 05 18 6f ?? 00 00 0a 1e 2c 39 11 05 18}  //weight: 1, accuracy: Low
        $x_1_2 = {1b 2c c8 26 18 2c bf 20 80 96 98 00 28 ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDBQ_2147846097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDBQ!MTB"
        threat_id = "2147846097"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "617bccd7-1937-43c6-92c4-e76807d8d9e0" ascii //weight: 1
        $x_1_2 = "Nfjyejcuamv" ascii //weight: 1
        $x_1_3 = "Hiqmvgrlsmnkzzwjztx" ascii //weight: 1
        $x_1_4 = "Uxxpoihse" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDBR_2147846099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDBR!MTB"
        threat_id = "2147846099"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4c05980b-52bd-4284-8a5e-8319c7f5a5a0" ascii //weight: 1
        $x_1_2 = "Mjmbjbvye" ascii //weight: 1
        $x_1_3 = "Vzfsudyqxyeotxqx" wide //weight: 1
        $x_1_4 = "Ldmwhtafhco" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RPY_2147846274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RPY!MTB"
        threat_id = "2147846274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 8e 69 8d 1e 00 00 01 0a 16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RPY_2147846274_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RPY!MTB"
        threat_id = "2147846274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 8e 69 5d 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 87 00 00 0a 03 08 1f 09 58 1e 59 03 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RPY_2147846274_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RPY!MTB"
        threat_id = "2147846274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 11 08 08 11 08 91 11 04 11 08 09 5d 91 61 d2 9c 1f 09 13 0f 38 6b ff ff ff 06 6f d2 00 00 0a 0b 19 13 0f 38 5c ff ff ff 11 08 2c 19 1b 13 0f 38 50 ff ff ff 16 13 08 1d 13 0f 38 45 ff ff ff 11 08 17 58 13 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RPY_2147846274_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RPY!MTB"
        threat_id = "2147846274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 02 06 02 06 91 66 d2 9c 02 06 8f 18 00 00 01 25 71 18 00 00 01 20 83 00 00 00 59 d2 81 18 00 00 01 02 06 8f 18 00 00 01 25 71 18 00 00 01 1f 25 58 d2 81 18 00 00 01 00 06 17 58 0a 06 02 8e 69 fe 04 0b 07 2d b9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_EH_2147846342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.EH!MTB"
        threat_id = "2147846342"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {07 09 18 6f 93 00 00 0a 1f 10 28 94 00 00 0a 13 06 08 17 8d 67 00 00 01 25 16 11 06 9c 6f 95 00 00 0a 00 09 18 58 0d 00 09 07 6f 96 00 00 0a fe 04 13 07 11 07 2d c8}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDBS_2147846887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDBS!MTB"
        threat_id = "2147846887"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 8e 69 5d 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDBU_2147847547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDBU!MTB"
        threat_id = "2147847547"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xjZnsNrPnm" ascii //weight: 1
        $x_1_2 = "hyhpSfRw9f3qfW4vYL" ascii //weight: 1
        $x_1_3 = "iwjko1VNO1vkpcmZws" ascii //weight: 1
        $x_1_4 = "aR3nbf8dQp2feLmk31" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDCA_2147848767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDCA!MTB"
        threat_id = "2147848767"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 07 6f 4c 00 00 0a 03 07 03 6f 6d 00 00 0a 5d 6f 4c 00 00 0a 61 0c 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MBEH_2147849062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MBEH!MTB"
        threat_id = "2147849062"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 40 1f 00 00 28 ?? 00 00 0a 20 f0 0f 00 00 28 ?? 00 00 0a 7e ?? 00 00 04 7e ?? 00 00 04 28 ?? 00 00 0a 0a 73 ?? 00 00 0a 7e ?? 00 00 04 06 6f ?? 00 00 0a 20 77 32 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDCF_2147849428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDCF!MTB"
        threat_id = "2147849428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Vouchorrummagy" ascii //weight: 1
        $x_1_2 = "dorayCatha" ascii //weight: 1
        $x_1_3 = "dorayEvens" ascii //weight: 1
        $x_1_4 = "cathaBandar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MBEQ_2147849501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MBEQ!MTB"
        threat_id = "2147849501"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "03-00-E2-00-03-00-E2-00-03-00-E2-00-03-00-00-00-E6" wide //weight: 1
        $x_1_2 = "94-40-4A-00-60-00-95-40-18-00-60-40-26-40-B5" wide //weight: 1
        $x_1_3 = {45 00 36 00 2d 00 30 00 30 00 2d 00 39 00 34 00 2d 00 30 00 30 00 2d 00 35 00 36 00 2d 00 30 00 30 00 2d 00 43 00 36 00 2d 00 30 00 30 00 2d 00 39 00 36 00 2d 00 30 00 30 00 2d 00 36 00 34 00 2d 00 30 00 30 00 2d 00 32 00 37 00 2d 00 30 00 30 00 2d 00 31 00 36 00 2d 00 30 00 30 00 2d 00 36 00 35 00 2d 00 30 00 30 00 2d 00 31 00 30 00 2d 00 30 00 30 00 2d 00 30 00 30 00 2d 00 30 00 30 00 2d 00 34 00 34}  //weight: 1, accuracy: High
        $x_1_4 = "36-37-D6-00-E6-96-16-D4-C6-C6-44-27-F6" wide //weight: 1
        $x_1_5 = "Load" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDCL_2147850786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDCL!MTB"
        threat_id = "2147850786"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Recycle Bio Lab Tool" ascii //weight: 1
        $x_1_2 = "BioTech" ascii //weight: 1
        $x_1_3 = "8rAa4GDHQdmFMXl0qL" ascii //weight: 1
        $x_1_4 = "eBrl844cQpr9ONZ5lE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDCM_2147850788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDCM!MTB"
        threat_id = "2147850788"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bcc6105e-5100-4348-b4fa-64ce9a4b2dff" ascii //weight: 1
        $x_1_2 = "Chrome" ascii //weight: 1
        $x_1_3 = "Hbnpkx" ascii //weight: 1
        $x_1_4 = "lFBy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MBHG_2147851735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MBHG!MTB"
        threat_id = "2147851735"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 ff a2 3f 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 fe 00 00 00 ee 00 00 00 e5 02 00 00 29 05 00 00 c0 04 00 00 0b 00 00 00 90 02 00 00 74 00 00 00 4c 02 00 00 11 00 00 00 01 00 00 00 26}  //weight: 1, accuracy: High
        $x_1_2 = {26 00 06 00 36 00 3f 00 06 00 51 00 62 00 06 00 69 00 62 00 06 00 73 00 62 00 06 00 7a 00 81 00 06 00 8b 00 62 00 06 00 92 00 99 00 0a 00 b4 00 bf 00 06 00 df 00 62}  //weight: 1, accuracy: High
        $x_1_3 = {43 6f 6e 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65 00 e2 80 8d e2 80 8c e2 80 aa e2 80 8e e2 81 ab e2 80 ab e2}  //weight: 1, accuracy: High
        $x_1_4 = {61 00 6c 00 61 00 6e 00 67 00 2e 00 65 00 78 00 65 00 00 00 00 00 72 00 27 00 01 00 4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 4e 00 69 00 72}  //weight: 1, accuracy: High
        $x_1_5 = "Lalang.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDCW_2147852344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDCW!MTB"
        threat_id = "2147852344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 06 28 3a 00 00 0a 0e 04 6f 3b 00 00 0a 6f 3c 00 00 0a 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDCY_2147852469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDCY!MTB"
        threat_id = "2147852469"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 09 a2 14 28 84 00 00 0a 1b 8c 57 00 00 01 28 8c 00 00 0a a2 14 28 8d 00 00 0a 00 09 08 12 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MBHQ_2147852644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MBHQ!MTB"
        threat_id = "2147852644"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dsfdsfdsfdsgfgdfgdgdsadfdsadffsdfdsgdgsdfsdfsdf" wide //weight: 1
        $x_1_2 = "C220A9B06007" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_NIE_2147852935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.NIE!MTB"
        threat_id = "2147852935"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 84 02 00 0a 26 02 28 ?? ?? 00 0a 0a 28 ?? ?? 00 0a 06 16 06 8e 69 6f ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "wyagc" ascii //weight: 1
        $x_1_3 = "uhgf6" ascii //weight: 1
        $x_1_4 = "BCRYPT_DSA_KEY_BLOB_V2S.Form3.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDDC_2147888294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDDC!MTB"
        threat_id = "2147888294"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "70a20485-a36f-4aae-bf34-4623e6bba783" ascii //weight: 1
        $x_1_2 = "CreamAPI_CSharp" ascii //weight: 1
        $x_1_3 = "CApiFileGest" ascii //weight: 1
        $x_1_4 = "mEqmoE9UxRmX9ogcto" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_ASCN_2147888307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.ASCN!MTB"
        threat_id = "2147888307"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 07 06 16 73 ?? 00 00 0a 0c 02 8e 69 8d ?? 00 00 01 0d 08 09 16 09 8e 69 6f ?? 00 00 0a 13 04 09 11 04 28 ?? 00 00 2b 28 ?? 00 00 2b 13 05 de 1e}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_AAMD_2147888517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.AAMD!MTB"
        threat_id = "2147888517"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 16 07 1f 0f 1f 10 28 ?? 00 00 0a 06 07 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 19 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_ASEF_2147891673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.ASEF!MTB"
        threat_id = "2147891673"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "9B88C78E81ADB9E7247AB37D1F5F3861810916D8" ascii //weight: 1
        $x_1_2 = "571B1023DF3ABFB94C92465B365B1814FEBFAB3E" ascii //weight: 1
        $x_1_3 = "asdasod9234oasd" ascii //weight: 1
        $x_1_4 = "adkasd8u3hbasd" ascii //weight: 1
        $x_1_5 = "autofillProfilesTotal of RAMVPEntity12N" wide //weight: 1
        $x_1_6 = "e94dff9a76da90d6b000642c4a52574b" wide //weight: 1
        $x_1_7 = "HCECWSk7MBgmHGVALQEgYTgLBB0fMQZbKwBIXA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDDJ_2147891846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDDJ!MTB"
        threat_id = "2147891846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 11 04 16 11 04 8e 69 6f a1 00 00 0a 13 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_SPAQ_2147892677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.SPAQ!MTB"
        threat_id = "2147892677"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 07 03 16 03 8e 69 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 00 02 28 ?? ?? ?? 0a 26 17 0d de 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDDX_2147895481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDDX!MTB"
        threat_id = "2147895481"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 07 1f 0a 5d 91 61 d2 81 ?? ?? ?? ?? 07 17 58 0b 07 03 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDDY_2147895497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDDY!MTB"
        threat_id = "2147895497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MyHealthLoader" ascii //weight: 1
        $x_1_2 = "XYZ Healthcare Solutions" ascii //weight: 1
        $x_1_3 = "CheckMyReg" ascii //weight: 1
        $x_1_4 = "MyNetworkApi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MBER_2147895838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MBER!MTB"
        threat_id = "2147895838"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fghfgsfffffdfdfdsfdasdfh" ascii //weight: 1
        $x_1_2 = "sgfhjffgdrfhdfdhffadfsfsscfdb" ascii //weight: 1
        $x_1_3 = "jffffffsdgkffff" ascii //weight: 1
        $x_1_4 = "hdffhhfhdggfhdfdfhdjfhdasffffkdf" ascii //weight: 1
        $x_1_5 = "kffsjggfffh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_KAB_2147896396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.KAB!MTB"
        threat_id = "2147896396"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5a 00 41 04 ea 05 2e 04 41 04 53 90 42 04 3a 04 21 09 48 06 3e 04 3e 04 48 06 39 06 2e 09 47 06 d1 05 2d}  //weight: 1, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "StrReverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_ABAW_2147896518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.ABAW!MTB"
        threat_id = "2147896518"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 1e 03 00 00 38 45 01 00 00 20 53 03 00 00 38 45 01 00 00 38 4a 01 00 00 26 16 3a 2e 01 00 00 20 85 00 00 00 38 43 01 00 00 20 85 00 00 00 38 43 01 00 00 38 48 01 00 00 38 4d 01 00 00 38 4e 01 00 00 16 39 4e 01 00 00 26 20 85 00 00 00 28 a4 00 00 06 06 02 28 8f 00 00 06 0a}  //weight: 1, accuracy: High
        $x_1_2 = "kpIAAkmhdl.resources" ascii //weight: 1
        $x_1_3 = "kpIAAkmhdl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDEE_2147897315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDEE!MTB"
        threat_id = "2147897315"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDEF_2147897731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDEF!MTB"
        threat_id = "2147897731"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 6f 7b 01 00 0a 02 14 7d fd 00 00 04 6f 7c 01 00 0a 7e fa 00 00 04 25}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_PTEW_2147900383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.PTEW!MTB"
        threat_id = "2147900383"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7b d9 00 00 04 61 28 ?? 00 00 06 7e 48 01 00 04 28 ?? 05 00 06 7e 49 01 00 04 28 ?? 05 00 06 13 31}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_PTFB_2147900423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.PTFB!MTB"
        threat_id = "2147900423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 ff c1 04 70 28 ?? 3f 00 06 28 ?? 2b 00 06 0d 09 28 ?? 00 00 0a 72 3b c2 04 70 6f 33 00 00 0a 13 04 07 72 5b c2 04 70 6f 34 00 00 0a 0c 11 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_PTFG_2147900467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.PTFG!MTB"
        threat_id = "2147900467"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f db 01 00 0a 13 05 28 ?? 02 00 06 13 06 11 06 11 05 17 73 dc 01 00 0a 25 06 16 06 8e 69 6f dd 01 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDEJ_2147900513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDEJ!MTB"
        threat_id = "2147900513"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 47 1f 7b 61 d2 52 06 17 58 0a 06 02 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDEM_2147900832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDEM!MTB"
        threat_id = "2147900832"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 0e 05 04 8e 69 6f ?? ?? ?? ?? 0a 06 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_GPA_2147901770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.GPA!MTB"
        threat_id = "2147901770"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 12 11 15 75 02 00 00 1b 11 16 11 08 58 11 19 59 93 61 07 75 02 00 00 1b 11 19 11 16 58 1f 11 58 11 10 5d 93 61 d1 7e 11 02 00 04 11 0a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDEO_2147902128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDEO!MTB"
        threat_id = "2147902128"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5d 13 0b 02 11 06 8f 1a 00 00 01 25 71 1a 00 00 01 06 11 0b 91 61 d2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_PTIY_2147903205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.PTIY!MTB"
        threat_id = "2147903205"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 e1 01 00 0a 25 02 16 02 8e 69 6f b1 02 00 0a 6f b3 02 00 0a 06 28 ?? 03 00 06 28 ?? 03 00 06 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_NN_2147903261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.NN!MTB"
        threat_id = "2147903261"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e e3 ?? ?? ?? 0e 06 17 59 e0 95 58 0e 05 28 37 03 ?? ?? 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_ARA_2147903394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.ARA!MTB"
        threat_id = "2147903394"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\Cookies_Mozilla.txt" ascii //weight: 2
        $x_2_2 = "\\Passwords_Mozilla.txt" ascii //weight: 2
        $x_2_3 = "win32_logicaldisk.deviceid=\"" ascii //weight: 2
        $x_2_4 = {07 06 08 1f 0a 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 05 12 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 11 04 17 58 13 04 11 04 09 fe 04 13 06 11 06 2d cb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDER_2147905185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDER!MTB"
        threat_id = "2147905185"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegexContinueParsing" ascii //weight: 1
        $x_1_2 = "UnwindSizeParamIndex" ascii //weight: 1
        $x_1_3 = "FromEndMonthEnd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MBZW_2147907392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MBZW!MTB"
        threat_id = "2147907392"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c 4d 6f 64 75 6c 65 3e 00 45 75 67 65 6e 65 00 4d 53 47 5f 4e 45 54 00 4f 62 6a 65 63 74 00 62 6c 56 76 37 77 4c 55 73 73 54 31 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_E_2147907978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.E!MTB"
        threat_id = "2147907978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dSMDZkEMfcHXWDTQdDXjWhWVIp.dll" ascii //weight: 1
        $x_1_2 = "cfROPfZPmqSedHYWQjDuXLNxTcKwe" ascii //weight: 1
        $x_1_3 = "ELhnRFQDkBJqpHoBMiEZrkkCCnTaR" ascii //weight: 1
        $x_1_4 = "uZNGrkwqzbURuKiDjwPutrarcR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDET_2147908510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDET!MTB"
        threat_id = "2147908510"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TechNova Solutions Suite" ascii //weight: 1
        $x_1_2 = "Leading innovation for a connected world." ascii //weight: 1
        $x_1_3 = "Alpha" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_KAO_2147910656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.KAO!MTB"
        threat_id = "2147910656"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 11 01 6f ?? 00 00 0a 03 11 01 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 13 02}  //weight: 1, accuracy: Low
        $x_1_2 = "AesManaged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_KAQ_2147913389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.KAQ!MTB"
        threat_id = "2147913389"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 75 59 d2 81 ?? 00 00 01 02 11 09 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 44 58 d2 81 ?? 00 00 01 00 11 09 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_KAR_2147914079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.KAR!MTB"
        threat_id = "2147914079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 05 91 11 07 61 13 08 11 05 17 58 08 5d 13 09 1f 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_KAS_2147914454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.KAS!MTB"
        threat_id = "2147914454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FSummFTmAIliP" ascii //weight: 1
        $x_1_2 = "EYEoQWYGtU" ascii //weight: 1
        $x_1_3 = "kgFSqkceBips" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_ASH_2147915023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.ASH!MTB"
        threat_id = "2147915023"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "hkinHOVKwPlEmquZROiLYbNQ" ascii //weight: 1
        $x_1_2 = "UNBYOuJrtMHrTNckymRgrNtblNKbc" ascii //weight: 1
        $x_1_3 = "PNLyWMKCPrIIyxaZxaEPeJzBVQwNM" ascii //weight: 1
        $x_1_4 = "caiuAVDXNSlNtmjSZtChZiepvwzxA" ascii //weight: 1
        $x_1_5 = "$e3d2f8a9-b7c5-4a23-8d12-65432abcde90" ascii //weight: 1
        $x_1_6 = "Pushing the boundaries of technology for a brighter tomorrow" wide //weight: 1
        $x_1_7 = {43 00 6f 00 73 00 6d 00 69 00 63 00 45 00 64 00 67 00 65 00 [0-34] 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDEW_2147915237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDEW!MTB"
        threat_id = "2147915237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AhnLab V3 Lite" ascii //weight: 1
        $x_1_2 = "GetDispatcher" ascii //weight: 1
        $x_2_3 = "ConnectDispatcher" ascii //weight: 2
        $x_2_4 = "SearchDispatcher" ascii //weight: 2
        $x_2_5 = "QueryDispatcher" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_KAT_2147915351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.KAT!MTB"
        threat_id = "2147915351"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rOkQrbpeBV.dll" ascii //weight: 1
        $x_1_2 = "gZLoqPRbcyvsC.dll" ascii //weight: 1
        $x_1_3 = "ozJXCUPHdtrmQ.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDEX_2147915529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDEX!MTB"
        threat_id = "2147915529"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "a1b2c3d4-e5f6-7890-abcd-12345ef67890" ascii //weight: 2
        $x_1_2 = "StellarTech Solutions" ascii //weight: 1
        $x_1_3 = "Innovative technologies for a connected future" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_ASKL_2147916404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.ASKL!MTB"
        threat_id = "2147916404"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 06 02 06 91 66 d2 9c 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 20 ?? 00 00 00 59 d2 81 ?? 00 00 01 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 58 d2 81 ?? 00 00 01 00 06 17 58 0a 06 02 8e 69 fe 04 0b 07 2d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDEY_2147916547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDEY!MTB"
        threat_id = "2147916547"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "efdd587d-41d5-442e-8f94-e0a31e5be97f" ascii //weight: 2
        $x_1_2 = "Huawei Share" ascii //weight: 1
        $x_1_3 = "Suite Pro" ascii //weight: 1
        $x_1_4 = "Leading-edge solutions for a connected world" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_ASI_2147916831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.ASI!MTB"
        threat_id = "2147916831"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wWRRxYrbKFxJQuFWjKjOpb.dll" ascii //weight: 1
        $x_1_2 = "QwsKTozhSPPEXgODRNYSxjJ.dll" ascii //weight: 1
        $x_1_3 = "NupwaMRcKCvjPkpuEpciMHRf" ascii //weight: 1
        $x_1_4 = "wSEAQLylSBYopApfUtryXTMHwZ.dll" ascii //weight: 1
        $x_1_5 = "zEpKgWZUobrageKc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDEZ_2147916925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDEZ!MTB"
        threat_id = "2147916925"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 05 08 5d 08 58 08 5d 91 11 06 61 11 08 59}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDFA_2147917312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDFA!MTB"
        threat_id = "2147917312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0c 08 6f 4b 00 00 0a 0d 09 03 16 03 8e 69 6f 4c 00 00 0a 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_NNA_2147917346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.NNA!MTB"
        threat_id = "2147917346"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {61 65 66 20 41 01 00 00 28 dd 07 00 06 61 2a}  //weight: 2, accuracy: High
        $x_1_2 = "f4a6c187-a863-488c-8473-d9711345a979" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MBXL_2147917382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MBXL!MTB"
        threat_id = "2147917382"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F7H8A87554B888QJH574E2" wide //weight: 1
        $x_1_2 = "0E85BYHUG4WS58578OHH7G" wide //weight: 1
        $x_1_3 = "Load" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MSIL_RedLine_KAP_2147917504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.KAP!MTB"
        threat_id = "2147917504"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {91 06 09 06 8e 69 5d 91 61 d2 9c 09 17 58 0d}  //weight: 1, accuracy: High
        $x_1_2 = {93 03 07 03 8e 69 5d 93 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDFB_2147917709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDFB!MTB"
        threat_id = "2147917709"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 11 20 02 11 20 91 66 d2 9c 02 11 20 8f 1d 00 00 01 25 71 1d 00 00 01 1f 64 58 d2 81 1d 00 00 01 02 11 20 8f 1d 00 00 01 25 71 1d 00 00 01 20 92 00 00 00 59 d2 81 1d 00 00 01 00 11 20 17 58 13 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_KAV_2147917998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.KAV!MTB"
        threat_id = "2147917998"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "369b0077-af55-437a-99f5-4f3939700d2d" ascii //weight: 1
        $x_1_2 = "Logitech G Innovations Trademark" ascii //weight: 1
        $x_1_3 = "Logitech G professional gaming keyboards are designed for competition" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDFC_2147918685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDFC!MTB"
        threat_id = "2147918685"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "2fd5dd05-0c12-4ab3-911c-c930a5602d87" ascii //weight: 2
        $x_1_2 = "IntelCore Innovations Trademark" ascii //weight: 1
        $x_1_3 = "professional gaming keyboards are designed for competition" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDFD_2147918690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDFD!MTB"
        threat_id = "2147918690"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 42 00 00 0a 28 43 00 00 0a 28 45 00 00 0a fe 0e dc 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDFE_2147918907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDFE!MTB"
        threat_id = "2147918907"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 02 6f 19 00 00 0a 8e 69 6f 1d 00 00 0a 28 01 00 00 2b 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDFF_2147919023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDFF!MTB"
        threat_id = "2147919023"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 72 61 00 00 70 28 44 00 00 0a 72 93 00 00 70 28 44 00 00 0a 6f 45 00 00 0a 0c 73 46 00 00 0a 0d 09 08 17 73 47 00 00 0a 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_ASJ_2147919077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.ASJ!MTB"
        threat_id = "2147919077"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ivUoPrIRwWqFIMxijsUHVFHSCibn.dll" ascii //weight: 1
        $x_1_2 = "IHNTVrprogXEDBHWyBbrh" ascii //weight: 1
        $x_1_3 = "qRmVQnoIUPFUYMzIrMyX.dll" ascii //weight: 1
        $x_1_4 = "BVOwwbvHCHPtoMBkJSvprcOBjdYEY" ascii //weight: 1
        $x_1_5 = "RCxeusRzzjFTaaSFIhiymtCgRUsfd.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_KAU_2147919571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.KAU!MTB"
        threat_id = "2147919571"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 08 04 08 1e 5d 9a 28 ?? 00 00 0a 03 08 91 28 ?? 01 00 06 28 ?? 00 00 0a 9c 08 17 d6 0c 08 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MBXS_2147919769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MBXS!MTB"
        threat_id = "2147919769"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {45 4e 58 63 50 75 4a 7a 00 e5 a5 bd e6 8f 90 e7 94 a8 e7 ad 94 e6 9d a5}  //weight: 3, accuracy: High
        $x_2_2 = "BigWerks.DripUnique" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDFG_2147919772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDFG!MTB"
        threat_id = "2147919772"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 6f ad 00 00 0a 28 ae 00 00 0a 0d 09 6f af 00 00 0a 16 9a 13 04 11 04 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDFH_2147919862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDFH!MTB"
        threat_id = "2147919862"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 11 13 8f 14 00 00 01 25 71 14 00 00 01 06 11 1c 91 61 d2 81 14 00 00 01 11 13 17 58 13 13 11 13 02 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_VHAA_2147920133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.VHAA!MTB"
        threat_id = "2147920133"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hfCplgsDCrEYPzHhMCLblsyZxtaq.dll" ascii //weight: 2
        $x_1_2 = "VItYkEpoRfCNjDiQcJIMzxGTId" ascii //weight: 1
        $x_1_3 = "qjTYpnwFdvcOwuIwCOHyQkUAmQk.dll" ascii //weight: 1
        $x_1_4 = "UvwhmxSsrMXOXwZdjcQZVXik" ascii //weight: 1
        $x_1_5 = "THkiFlhhlkJHcHrYCaPGyZVfH.dll" ascii //weight: 1
        $x_1_6 = "MsbyFHwIWjnngFHPGYW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MBXT_2147920580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MBXT!MTB"
        threat_id = "2147920580"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8d 30 00 00 01 13 0a 11 09 11 0a 16 11 0a 8e 69 6f cc 00 00 0a 26 11 09 28 4e 1d 00 06 16 13 0b 14 13 0c}  //weight: 3, accuracy: High
        $x_2_2 = "template832components" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDFI_2147921746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDFI!MTB"
        threat_id = "2147921746"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "6c4eb187-d421-48d3-bd24-34c30b560a6d" ascii //weight: 2
        $x_1_2 = "EuroSpar Inc OptiTech Suite" ascii //weight: 1
        $x_1_3 = "Shaping immersive experiences through visionary optics and digital innovation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_KAY_2147921805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.KAY!MTB"
        threat_id = "2147921805"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 11 34 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 35 91 61 d2 81 ?? 00 00 01 de 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDFJ_2147922437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDFJ!MTB"
        threat_id = "2147922437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 6f 68 00 00 0a 16 9a 13 05 11 05 6f 69 00 00 0a 16 9a 13 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDFK_2147924029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDFK!MTB"
        threat_id = "2147924029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 28 bf 00 00 0a 0c 28 c0 00 00 0a 6f c1 00 00 0a 08 6f c2 00 00 0a 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDFK_2147924029_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDFK!MTB"
        threat_id = "2147924029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {91 66 d2 9c 02 06 8f 36 00 00 01 25 71 36 00 00 01 1f 79 59 d2 81 36 00 00 01 02 06 8f 36 00 00 01 25 71 36 00 00 01 1f 57 59 d2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDFL_2147924667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDFL!MTB"
        threat_id = "2147924667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 12 02 28 43 00 00 0a 9c 25 17 12 02 28 44 00 00 0a 9c 25 18 12 02 28 45 00 00 0a 9c 6f 46 00 00 0a 00 00 11 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDFN_2147925233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDFN!MTB"
        threat_id = "2147925233"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 06 6f 2d 00 00 0a 06 6f 2e 00 00 0a 6f 2f 00 00 0a 03 6f 2a 00 00 0a 16 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDFO_2147926070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDFO!MTB"
        threat_id = "2147926070"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 28 15 00 00 06 13 06 11 05 11 06 16 11 06 8e 69 6f 24 00 00 0a 28 16 00 00 06 13 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_BJ_2147926137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.BJ!MTB"
        threat_id = "2147926137"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 26 06 6f ?? ?? 00 0a 0b 00 03 6f ?? ?? 00 0a 05 fe 04 16 fe 01 0c 08 2c ?? 2b ?? 02 03 04 07 05 28 ?? 00 00 06 00 00 06 6f}  //weight: 2, accuracy: Low
        $x_2_2 = {02 04 05 28 ?? 00 00 06 0a 0e 04 03 6f ?? ?? 00 0a 59 0b 03 06 07 28 ?? 00 00 06 00 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_RDFP_2147926218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.RDFP!MTB"
        threat_id = "2147926218"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 1f 00 00 0a 73 20 00 00 0a 20 20 02 00 00 6f 21 00 00 0a 2a}  //weight: 2, accuracy: High
        $x_1_2 = "2a55bbea-a55f-4641-aac7-4e0d1b3dee65" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_MBWC_2147927277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.MBWC!MTB"
        threat_id = "2147927277"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {49 37 33 66 31 77 77 51 47 36 00 4b 6d 39 4c 53 6f 44 6b 61 47 66 37 66 4c 4a 4c 77 71 66 00 42 67 30 63 63 55 44 68 75 62 31 44}  //weight: 2, accuracy: High
        $x_1_2 = "instruction_manual.Resources.resourc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLine_ACG_2147943735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLine.ACG!MTB"
        threat_id = "2147943735"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 07 08 6f ?? 00 00 0a 13 06 04 03 6f ?? 00 00 0a 59 13 07 11 07 19 fe 04 16 fe 01}  //weight: 3, accuracy: Low
        $x_2_2 = {07 11 04 5a 08 58 13 08 06 11 08 17 6f ?? 00 00 0a 00 1a 13 05 2b 1b 08 17 58 0c 18}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

