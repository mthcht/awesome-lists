rule Trojan_MSIL_Dcstl_ABD_2147833101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.ABD!MTB"
        threat_id = "2147833101"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 08 08 16 08 8e 69 6f ?? ?? ?? 0a 00 11 08 6f ?? ?? ?? 0a 00 06 13 09 11 09 07 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 09 11 09 11 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 09 11 07 6f ?? ?? ?? 0a 00 11 08 6f ?? ?? ?? 0a 00 11 09 28 ?? ?? ?? 0a 13 0a de 3f}  //weight: 4, accuracy: Low
        $x_1_2 = "FlushFinalBlock" ascii //weight: 1
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "Anti HTTP Debugger" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_ABBH_2147834309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.ABBH!MTB"
        threat_id = "2147834309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadData" ascii //weight: 1
        $x_1_2 = "Clipboard" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "$be29c2ec-8a8f-4c19-b50b-4263c88e609d" ascii //weight: 1
        $x_1_5 = "Discord_Checker.Properties.Resources" wide //weight: 1
        $x_1_6 = "lzt_logo" wide //weight: 1
        $x_1_7 = "photo_2021_07_01_16_31_02_removebg_preview__1_" wide //weight: 1
        $x_1_8 = "telegram_PNG33" wide //weight: 1
        $x_1_9 = "tenor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_ABCQ_2147835242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.ABCQ!MTB"
        threat_id = "2147835242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 11 04 91 13 05 00 07 08 11 05 03 61 d2 9c 08 17 58 0c 00 11 04 17 58 13 04 11 04 09 8e 69 32 df}  //weight: 2, accuracy: High
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "CryingWolf.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_NF_2147836557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.NF!MTB"
        threat_id = "2147836557"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 6f 65 00 00 0a 73 ?? ?? ?? 0a 0a 06 28 ?? ?? ?? 06 0b 07 2c 02 07 2a 7e ?? ?? ?? 04 7e ?? ?? ?? 04 06 28 ?? ?? ?? 06 0b}  //weight: 5, accuracy: Low
        $x_1_2 = "costura.metadata" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "LoWiBot" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_NDY_2147836560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.NDY!MTB"
        threat_id = "2147836560"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 13 00 00 0a 28 ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 08 72 ?? ?? ?? 70 28 ?? ?? ?? 06 2c 28 02 08 72 ?? ?? ?? 70 28 ?? ?? ?? 06 72 ?? ?? ?? 70 08 72 ?? ?? ?? 70 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 17 73 ?? ?? ?? 06 2a 02 72 ?? ?? ?? 70 16 73 ?? ?? ?? 06 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "copy2startup" ascii //weight: 1
        $x_1_3 = "DownloadString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_NA_2147837608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.NA!MTB"
        threat_id = "2147837608"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "://icanhazip.com/" wide //weight: 5
        $x_5_2 = "DownloadString" ascii //weight: 5
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "GetFolderPath" ascii //weight: 1
        $x_1_5 = "encrypted_key" wide //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_8 = "SpreadMode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_NKL_2147838701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.NKL!MTB"
        threat_id = "2147838701"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 18 06 28 ?? ?? ?? 06 2a 20 ?? ?? ?? c9 0d 07 20 ?? ?? ?? ff 5a 09 61 2b c1}  //weight: 5, accuracy: Low
        $x_5_2 = {28 67 00 00 06 0b 07 2d 08 20 ?? ?? ?? ea 25 2b 06 20 ?? ?? ?? 9c 25 26 11 07 20 ?? ?? ?? 42 5a 61 38 ?? ?? ?? ff 7e ?? ?? ?? 04 7e ?? ?? ?? 04 06 28 ?? ?? ?? 06}  //weight: 5, accuracy: Low
        $x_1_3 = "://server1.stumblepriv.xyz" wide //weight: 1
        $x_1_4 = "accesskey_h1565933142" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_NP_2147838855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.NP!MTB"
        threat_id = "2147838855"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 28 a5 00 00 0a 25 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 25 74 ?? ?? ?? 01 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Chaoap" wide //weight: 1
        $x_1_3 = "GCleaner.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_NDT_2147839727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.NDT!MTB"
        threat_id = "2147839727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 1f 00 00 06 0d 09 17 6f ?? 00 00 0a 09 04 07 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 11 05 11 04 17 73 ?? 00 00 0a 13 06 03 6f ?? 00 00 0a 13 07 11 06 11 07 16 11 07 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 08 11 05}  //weight: 5, accuracy: Low
        $x_1_2 = "LaserPrinter.Properties.Resources" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_NEAE_2147839870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.NEAE!MTB"
        threat_id = "2147839870"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 28 15 00 00 0a 0a 28 06 00 00 06 0b 07 07 6f 16 00 00 0a 07 6f 17 00 00 0a 6f 18 00 00 0a 25 06 16 06 8e 69 6f 19 00 00 0a 0c 6f 1a 00 00 0a 28 0f 00 00 0a 08 6f 1b 00 00 0a 2a}  //weight: 10, accuracy: High
        $x_2_2 = "Release\\Setup.pdb" ascii //weight: 2
        $x_2_3 = "AbaddonStub.Start" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_NEAF_2147840210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.NEAF!MTB"
        threat_id = "2147840210"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {07 6f 16 00 00 0a 00 73 17 00 00 0a 0c 08 6f 18 00 00 0a 72 13 02 00 70 6f 19 00 00 0a 00 08 6f 18 00 00 0a 17 6f 1a 00 00 0a 00 08 6f 18 00 00 0a 17 6f 1b 00 00 0a 00 08 6f 18 00 00 0a 17 6f 1c 00 00 0a 00 07 28 1e 00 00 0a 0c 2a}  //weight: 10, accuracy: High
        $x_2_2 = "C:\\Windows\\Logs" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_MA_2147841606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.MA!MTB"
        threat_id = "2147841606"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 00 73 29 00 00 0a 0b 07 72 25 02 00 70 02 6f 2a 00 00 0a 00 06 72 35 02 00 70 72 2a 03 00 70 07 6f 2b 00 00 0a 26 00 de 10}  //weight: 5, accuracy: High
        $x_3_2 = {73 75 70 65 72 73 65 78 5f [0-133] 2e 65 78 65}  //weight: 3, accuracy: Low
        $x_2_3 = "://icanhazip.com" wide //weight: 2
        $x_2_4 = "GetCPUID" ascii //weight: 2
        $x_2_5 = "GetGuid" ascii //weight: 2
        $x_2_6 = "SOFTWARE\\Microsoft\\Cryptography" wide //weight: 2
        $x_2_7 = "GetMacAddress" ascii //weight: 2
        $x_2_8 = "GetMachineGuid" ascii //weight: 2
        $x_2_9 = "SendMessageToDiscord" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_MB_2147841775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.MB!MTB"
        threat_id = "2147841775"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 01 00 00 70 0a 73 17 00 00 0a 0b 07 6f 18 00 00 0a 72 f6 00 00 70 72 10 01 00 70 6f 19 00 00 0a 00 72 32 01 00 70 02 72 4e 01 00 70 28 1a 00 00 0a 0c 07 06 28 1b 00 00 0a 08 6f 1c 00 00 0a 6f 1d 00 00 0a 26 2a}  //weight: 5, accuracy: High
        $x_2_2 = "testing_web.exe" ascii //weight: 2
        $x_1_3 = "1265309a-3806-4a29-82cf-294b3f2711e5" ascii //weight: 1
        $x_1_4 = "UploadData" ascii //weight: 1
        $x_1_5 = "GetLocalIPAddress" ascii //weight: 1
        $x_1_6 = "GetHostEntry" ascii //weight: 1
        $x_1_7 = "GetHostName" ascii //weight: 1
        $x_1_8 = "IPHostEntry" ascii //weight: 1
        $x_1_9 = "SendMs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_NDG_2147842652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.NDG!MTB"
        threat_id = "2147842652"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 b8 19 00 70 28 ?? ?? 00 0a 0d 09 28 ?? ?? 00 0a 13 05 11 05 2c 13 00 07 72 ?? ?? 00 70 28 ?? ?? 00 0a 28 ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "CompilerModule.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_PSLG_2147846130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.PSLG!MTB"
        threat_id = "2147846130"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 18 28 bd 00 00 0a 28 ?? ?? ?? 0a 25 26 72 f7 0a 00 70 28 ?? ?? ?? 0a 25 26 6f ?? ?? ?? 0a 25 26 0d 28 ?? ?? ?? 0a 25 26 72 7a 0b 00 70 28 6c 00 00 0a 25 26}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_PSMZ_2147846285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.PSMZ!MTB"
        threat_id = "2147846285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8e 69 28 1f 00 00 0a 07 2a 28 0b 00 00 06 2b ce 0a 2b cd 28 20 00 00 0a 2b ce 06 2b cd 6f 21 00 00 0a 2b c8 28 05 00 00 06 2b c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_PSOZ_2147847873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.PSOZ!MTB"
        threat_id = "2147847873"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 73 1a 00 00 0a 0a 72 16 01 00 70 17 73 1b 00 00 0a 0b 06 07 28 ?? ?? ?? 0a 72 d7 01 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 28 ?? ?? ?? 0a 72 d7 01 00 70 28 ?? ?? ?? 0a 28 1e 00 00 0a 26 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_PSPC_2147847896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.PSPC!MTB"
        threat_id = "2147847896"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 28 7d 00 00 0a 02 6f ?? ?? ?? 0a 0a 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 0b 06 73 ?? ?? ?? 0a 0c 08 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 0d 2b 00 09 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_PSRU_2147850756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.PSRU!MTB"
        threat_id = "2147850756"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 0a 00 00 06 73 0f 00 00 0a 72 4a 01 00 70 72 07 02 00 70 6f 18 00 00 0a 72 07 02 00 70 28 09 00 00 06 72 3f 02 00 70 28 19 00 00 0a 26 72 87 02 00 70 28 19 00 00 0a 26 72 d5 02 00 70 28 19 00 00 0a 26 16 28 1a 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_NST_2147852197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.NST!MTB"
        threat_id = "2147852197"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7b d4 01 00 04 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 25 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "AIO_Tool.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_CR_2147892367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.CR!MTB"
        threat_id = "2147892367"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 19 00 00 70 6f ?? ?? ?? 06 00 06 72 ?? ?? ?? 70 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "RozbehTheRobber" ascii //weight: 1
        $x_1_3 = "Adware HOAX" wide //weight: 1
        $x_1_4 = "Concat" ascii //weight: 1
        $x_1_5 = "DcWebHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_PTBU_2147896532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.PTBU!MTB"
        threat_id = "2147896532"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 14 01 00 70 28 ?? 00 00 0a 10 00 73 2a 00 00 0a 0b 02 28 ?? 00 00 0a 0c 16 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_PTBZ_2147896766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.PTBZ!MTB"
        threat_id = "2147896766"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 72 fd 03 00 70 28 ?? 00 00 0a 6f 17 00 00 0a 0a 72 48 05 00 70 0b 72 52 05 00 70}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_PTCL_2147897164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.PTCL!MTB"
        threat_id = "2147897164"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {17 73 39 00 00 0a 7e 02 00 00 04 6f 3a 00 00 0a 13 05 11 04 11 05 16 11 05 8e 69 6f 3b 00 00 0a 00 00 de 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_PTCM_2147897165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.PTCM!MTB"
        threat_id = "2147897165"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 2c 07 09 6f 46 00 00 0a 00 dc 28 ?? 00 00 0a 08 6f 5f 00 00 0a 6f 60 00 00 0a 13 04 de 16}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_PTCN_2147897166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.PTCN!MTB"
        threat_id = "2147897166"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 07 9a 0c 00 08 28 ?? 00 00 0a 0d 02 04 09 28 ?? 00 00 0a 6f 1f 00 00 0a 13 04 11 04 6f 20 00 00 0a 13 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_PSAK_2147899284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.PSAK!MTB"
        threat_id = "2147899284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DebuggingModes" ascii //weight: 1
        $x_1_2 = "AesCryptoServiceProvider" ascii //weight: 1
        $x_1_3 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_4 = "RijndaelManaged" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "ComputeHash" ascii //weight: 1
        $x_1_7 = "BCWvcNW0JxYlKMQuIxi" ascii //weight: 1
        $x_1_8 = "nryTCbWA78HKxE0fkgq" ascii //weight: 1
        $x_1_9 = "VsFyvWZmAu9QgonVgtb" ascii //weight: 1
        $x_1_10 = "mdLLoLW7YBk5sj4CjK4" ascii //weight: 1
        $x_1_11 = "SKLSboZDCdXBqKMhjfU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_PSET_2147899364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.PSET!MTB"
        threat_id = "2147899364"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 47 00 00 0a 13 04 72 c9 02 00 70 28 ?? ?? ?? 0a 13 05 11 04 11 05 16 11 05 8e 69 73 ?? ?? ?? 0a 72 df 02 00 70 72 c9 02 00 70 6f ?? ?? ?? 0a 09 7e 07 00 00 04 11 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 72 c9 02 00 70 28 ?? ?? ?? 0a de 1c}  //weight: 5, accuracy: Low
        $x_1_2 = "DebuggingModes" ascii //weight: 1
        $x_1_3 = "WriteLine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_EAAA_2147902724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.EAAA!MTB"
        threat_id = "2147902724"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 04 11 04 13 05 11 05 28 ?? 00 00 0a 13 06 28 ?? 00 00 06 28 ?? 00 00 0a 13 07 1a 8d ?? 00 00 01 25 16 20 08 00 00 00 28 ?? 00 00 06 a2 25 17 7e ?? 00 00 0a a2 25 18 11 06 a2 25 19 17 8c ?? 00 00 01 a2 13 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_OUAA_2147912483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.OUAA!MTB"
        threat_id = "2147912483"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 11 04 91 11 05 61 13 06 11 04 17 58 07 8e 69 5d 13 07 07 11 07 91 13 08 11 06 11 08 59 13 09 07 11 04 11 09 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 00 11 04 17 58 13 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_ZHAA_2147923325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.ZHAA!MTB"
        threat_id = "2147923325"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 00 09 07 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 07 73 ?? 00 00 0a 13 04 11 04 11 07 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 00 11 05 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 0c 00 00 de 39}  //weight: 3, accuracy: Low
        $x_1_2 = "L o a d" wide //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dcstl_ASKA_2147941512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcstl.ASKA!MTB"
        threat_id = "2147941512"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0a 06 20 00 01 00 00 6f ?? 00 00 0a 06 20 00 01 00 00 6f ?? 00 00 0a 06 72 15 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 6f 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b}  //weight: 3, accuracy: Low
        $x_2_2 = {08 11 05 16 11 06 6f ?? 00 00 0a 11 04 11 05 16 11 05 8e 69 6f ?? 00 00 0a 25 13 06 16 3d}  //weight: 2, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

