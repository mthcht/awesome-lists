rule Trojan_MSIL_Mamut_EYE_2147826896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.EYE!MTB"
        threat_id = "2147826896"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "5h6j2ijgr32i4325h4u5kjh2ji3234i635to" ascii //weight: 1
        $x_1_2 = "$1c4f25e8-0487-42ed-ac7e-7b605a27d33a" ascii //weight: 1
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggingModes" ascii //weight: 1
        $x_1_5 = "QuantumBuilder" ascii //weight: 1
        $x_1_6 = "GetExecutingAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_MBU_2147838481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.MBU!MTB"
        threat_id = "2147838481"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 13 05 08 28 ?? 00 00 0a 04 6f ?? 00 00 0a 6f ?? 00 00 0a 25 16 11 05 16 1f 10 28 ?? 00 00 0a 16 11 05 1f 0f 1f 10 28 ?? 00 00 0a 07 11 05}  //weight: 1, accuracy: Low
        $x_1_2 = "BE14D8CB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_RPQ_2147838787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.RPQ!MTB"
        threat_id = "2147838787"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 2d cc 11 04 11 05 09 11 05 09 8e 69 5d 91 07 11 05 91 61 d2 9c 11 05 17 58 13 05 11 05 07 8e 69 16 2d fc 32 da 11 04 13 06 1b 2c d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_RPU_2147840896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.RPU!MTB"
        threat_id = "2147840896"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 7b 06 00 00 04 6f 11 00 00 0a 18 1f 64 02 7b 03 00 00 04 5b 6b 73 14 00 00 0a 6f 15 00 00 0a 26 06 17 58 0a 06 02 7b 03 00 00 04 fe 04 0b 07 2d ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_GFM_2147842672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.GFM!MTB"
        threat_id = "2147842672"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 03 50 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 73 0d 00 00 0a 0c 08 07 6f ?? ?? ?? 0a 08 18 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 02 50 16 02 50 8e 69 6f ?? ?? ?? 0a 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_GFK_2147845124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.GFK!MTB"
        threat_id = "2147845124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateEncryptor" ascii //weight: 1
        $x_1_2 = "POWERSHELL" ascii //weight: 1
        $x_1_3 = "api.paste.ee/v1/pastes" ascii //weight: 1
        $x_1_4 = "Ionic.Zip" ascii //weight: 1
        $x_1_5 = "Doscan.exe" ascii //weight: 1
        $x_1_6 = "SELECT PROCESSID FROM WIN32_PROCESS WHERE PARENTPROCESSID = {0}" ascii //weight: 1
        $x_1_7 = "SeIncreaseQuotaPrivilege" ascii //weight: 1
        $x_1_8 = "SELECT PROCESSID, NAME, CREATIONDATE, COMMANDLINE FROM WIN32_PROCESS WHERE NAME = '{0}'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_AA_2147845581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.AA!MTB"
        threat_id = "2147845581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 28 28 00 00 06 07 8e 69 5e 13 04 08 09 07 11 04 e0 9a a2 09 17 58 0d 00 09 06 fe 04 13 16 11 16 2d db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_NM_2147846351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.NM!MTB"
        threat_id = "2147846351"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 26 00 00 0a d0 ?? ?? ?? 1b 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 74 0e 00}  //weight: 5, accuracy: Low
        $x_1_2 = "Packman" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_NM_2147846351_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.NM!MTB"
        threat_id = "2147846351"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Private Spoofer by Lev" ascii //weight: 2
        $x_2_2 = "AsStrongAsFuck obfuscator by Charter" ascii //weight: 2
        $x_2_3 = "LevsSpoofer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_KAB_2147851490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.KAB!MTB"
        threat_id = "2147851490"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 6a 0b 08 28 ?? 00 00 0a 23 00 00 00 00 00 00 e0 3f 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 07 17 6a 58 0b 07 20}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_AAHA_2147851556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.AAHA!MTB"
        threat_id = "2147851556"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {04 07 08 16 6f ?? 00 00 0a 13 05 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 06 3a ?? 00 00 00 26}  //weight: 4, accuracy: Low
        $x_1_2 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_AMAB_2147852135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.AMAB!MTB"
        threat_id = "2147852135"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {14 0c 2b 4a 02 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 6f ?? 00 00 0a 10 00 02 6f ?? 00 00 0a 18 5b 8d ?? 00 00 01 0a 16 0b 2b 18 06 07 02 07 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 07 17 58 0b 07 06 8e 69 fe 04 0d 09 2d de}  //weight: 1, accuracy: Low
        $x_1_2 = {31 00 34 00 43 00 43 00 44 00 32 00 31 00 35 00 34 00 36 00 38 00 36 00 39 00 37 00 33 00 32 00 2e 00 37 00 2e 00 37 00 32 00 36 00 46 00 36 00 37 00 37 00 32 00 36 00 31 00 36 00 44 00 32 00 2e 00 36 00 33 00 36 00 31 00 36 00 45 00 36 00 45 00 36 00 46 00 37 00 34 00 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_AFYN_2147891595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.AFYN!MTB"
        threat_id = "2147891595"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 25 2e 42 07 17 59 16 31 0d 02 07 17 59 6f ?? ?? ?? 0a 1f 25 2e 2f 07 17 58 02 6f ?? ?? ?? 0a 2f 0d 02 07 17 58 6f ?? ?? ?? 0a 1f 25 2e 17 11 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_AMAA_2147892239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.AMAA!MTB"
        threat_id = "2147892239"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 73 ?? 00 00 0a 0b 02 28 ?? 00 00 06 75 ?? 00 00 1b 73 ?? 00 00 0a 0c 08 11 04 16 73 ?? 00 00 0a 0d 09 07 6f ?? 00 00 0a 07 13 05 de 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_KAD_2147892851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.KAD!MTB"
        threat_id = "2147892851"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 06 02 07 91 6f ?? 00 00 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08 2d e8}  //weight: 5, accuracy: Low
        $x_5_2 = {00 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 07 11 04 16 11 05 6f ?? 00 00 0a 00 00 11 05 16 fe 02 13 06 11 06 2d d8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_KAE_2147892852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.KAE!MTB"
        threat_id = "2147892852"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 07 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 08 11 08 02 16 02 8e 69 6f ?? 00 00 0a 11 08 6f ?? 00 00 0a 11 07 6f ?? 00 00 0a 13 04 de 18}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_KAF_2147892853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.KAF!MTB"
        threat_id = "2147892853"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 02 16 06 6e 28 ?? 00 00 0a 02 8e 69 28 ?? 00 00 0a 00 06 6e 28 ?? 00 00 0a 02 8e 69 6a 28 ?? 00 00 0a 7e ?? 00 00 04 12 01 28}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_AMT_2147897282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.AMT!MTB"
        threat_id = "2147897282"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 11 04 17 73 ?? 00 00 0a 0c 28 ?? 06 00 06 0d 08 09 16 09 8e 69 6f ?? 00 00 0a 07 6f ?? 00 00 0a 13 05 de 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_AMT_2147897282_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.AMT!MTB"
        threat_id = "2147897282"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 11 04 13 09 16 13 0a 2b 28 11 09 11 0a 9a 13 05 7e 01 00 00 04 1f 64 33 05 16 13 06 de 1d 11 05 28 ?? ?? ?? 06 26 de 03 26 de 00 11 0a 17 58 13 0a 11 0a 11 09 8e 69 32 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_PSPQ_2147897589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.PSPQ!MTB"
        threat_id = "2147897589"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 02 6f 27 00 00 06 6f ?? ?? ?? 0a 73 ?? ?? ?? 0a 7d 0b 00 00 04 02 6f ?? ?? ?? 06 72 fd 01 00 70 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 02 7b 0b 00 00 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 02 20 e8 03 00 00 28 ?? ?? ?? 0a 7d 0e 00 00 04 02 28 16 00 00 06 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_AMU_2147900522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.AMU!MTB"
        threat_id = "2147900522"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0c 2b 34 16 0a 16 0d 2b 18 00 06 02 09 6f 80 00 00 0a 03 09 6f 80 00 00 0a 61 60 0a 00 09 17 58 0d 09 02 6f 15 00 00 0a fe 04 13 04 11 04 2d d9}  //weight: 1, accuracy: High
        $x_1_2 = {0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f 78 00 00 0a 1f 10 28 7f 00 00 0a 9c 08 18 58 0c 08 06 fe 04 0d 09 2d e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_LL_2147901186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.LL!MTB"
        threat_id = "2147901186"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 17 58 07 8e b7 ?? ?? ?? ?? ?? 07 09 93 0c 07 09 07 09 17 58 93 9d 07 09 17 58 08 9d 00 09 18 58 0d 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_NN_2147902543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.NN!MTB"
        threat_id = "2147902543"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 06 02 09 6f ?? ?? ?? ?? 03 09 6f 7f ?? ?? ?? 61 60 0a 00 09 17 58 0d 09 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_ARA_2147923216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.ARA!MTB"
        threat_id = "2147923216"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Anti Virus Detected" wide //weight: 2
        $x_2_2 = "\\Windows\\INF\\Windows Operating System Boot Enabler.exe" wide //weight: 2
        $x_2_3 = "\\System Files\\Backup\\Windows Backup.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_ARAF_2147927388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.ARAF!MTB"
        threat_id = "2147927388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "satabate.Resources" ascii //weight: 2
        $x_2_2 = "$3645D93A-AFBF-4B56-BC8A-E12A5A0BA6BA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_NK_2147928372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.NK!MTB"
        threat_id = "2147928372"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PustakaSoal.Resources.resources" ascii //weight: 2
        $x_2_2 = "AntiBitDefender" ascii //weight: 2
        $x_2_3 = "AntiAvast" ascii //weight: 2
        $x_1_4 = "Vindexer.exe" ascii //weight: 1
        $x_1_5 = "addMateriKhususUSB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mamut_NT_2147939124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mamut.NT!MTB"
        threat_id = "2147939124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {28 36 00 00 0a 7e 01 00 00 04 02 1a 58 08 6f 37 00 00 0a 28 38 00 00 0a a5 01 00 00 1b 0b 11 08 20 e5 35 0c 49 5a 20 38 6c 42 4a 61}  //weight: 3, accuracy: High
        $x_1_2 = "Autokeoxe.pdb" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

