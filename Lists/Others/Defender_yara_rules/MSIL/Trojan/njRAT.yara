rule Trojan_MSIL_njRAT_RDF_2147833885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDF!MTB"
        threat_id = "2147833885"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "nzwezwtzwszwh" wide //weight: 1
        $x_1_2 = "fizwrzwezwwalzwl dzwezwlzwezwte azwllowedprogrzwam \"" wide //weight: 1
        $x_1_3 = "cmd.exe" wide //weight: 1
        $x_1_4 = "/c ping 0 -n 2 & del \"" wide //weight: 1
        $x_2_5 = {11 05 11 06 9a 0b 07 6f 86 00 00 0a 72 ?? ?? ?? ?? 03 28 5e 00 00 0a 6f 87 00 00 0a 2c ?? 06 6f 88 00 00 0a 07 6f 86 00 00 0a 6f 89 00 00 0a 0c de ?? 11 06 17 58 13 06 11 06 11 05 8e 69}  //weight: 2, accuracy: Low
        $x_2_6 = {28 11 00 00 0a 6f 2c 00 00 0a 1f 1d 0f 00 1a 28}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDG_2147834167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDG!MTB"
        threat_id = "2147834167"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 06 18 58 93 1f 10 62 08 58 0c 1e}  //weight: 2, accuracy: High
        $x_1_2 = "kernel32" ascii //weight: 1
        $x_1_3 = "Sleep" ascii //weight: 1
        $x_1_4 = "RijndaelManaged" ascii //weight: 1
        $x_1_5 = "PasswordDeriveBytes" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDH_2147834168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDH!MTB"
        threat_id = "2147834168"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 06 18 58 93 1f 10 62 08 58 0c 1d 13 09 1e}  //weight: 2, accuracy: High
        $x_2_2 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1f 0f}  //weight: 2, accuracy: High
        $x_1_3 = "kernel32" ascii //weight: 1
        $x_1_4 = "Sleep" ascii //weight: 1
        $x_1_5 = "RijndaelManaged" ascii //weight: 1
        $x_1_6 = "PasswordDeriveBytes" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDA_2147834556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDA!MTB"
        threat_id = "2147834556"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 00 55 00 31 00 45 00 49 00 46 00 42 00 79 00 62 00 32 00 4e 00 6c 00 63 00 33 00 4e 00 76 00 63 00 69 00 ?? ?? 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "AMD Processor" wide //weight: 1
        $x_2_3 = {16 6a 6f 45 00 00 0a 11 04 6f 46 00 00 0a 25 26 13 09 11 09 6f 47 00 00 0a 25 26 13 0a 11 09 6f 48 00 00 0a 25 26 26 11 09 6f 48 00 00 0a 25 26 8d 03 00 00 01 13 0b 11 09 6f 47 00 00 0a 25 26 8d 03 00 00 01 13 0c 03 6f 49 00 00 0a 69 13 0d}  //weight: 2, accuracy: High
        $x_2_4 = {26 16 02 03 04 6f 0c 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDD_2147835628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDD!MTB"
        threat_id = "2147835628"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 07 02 07 91 08 1f 1f 5f 62 02 07 91 1e 08 59 1f 1f 5f 63 60 d2 9c 1a 0d}  //weight: 2, accuracy: High
        $x_1_2 = "ConfuserEx" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDE_2147835629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDE!MTB"
        threat_id = "2147835629"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ParameterizedThreadStart" ascii //weight: 1
        $x_2_2 = {02 50 06 02 50 06 91 03 06 03 6f 07 00 00 0a 5d 6f 08 00 00 0a 61 d2 9c 06 17 58 0a 06 02 50 8e 69 fe 04 0b 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDJ_2147837023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDJ!MTB"
        threat_id = "2147837023"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "9920AB83-0358-4D47-9715-60C515A71F7D" ascii //weight: 1
        $x_1_2 = "LoadLibrary" ascii //weight: 1
        $x_1_3 = "GetCurrentProcessId" ascii //weight: 1
        $x_1_4 = "GetProcAddress" ascii //weight: 1
        $x_1_5 = "OpenProcess" ascii //weight: 1
        $x_1_6 = "CloseHandle" ascii //weight: 1
        $x_1_7 = "GetILGenerator" ascii //weight: 1
        $x_1_8 = "CreateDelegate" ascii //weight: 1
        $x_1_9 = "ILGenerator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBS_2147838136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBS!MTB"
        threat_id = "2147838136"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 5c 11 5a 11 5b 16 6f ?? 00 00 0a 13 5e 12 5e 28 ?? 00 00 0a 6f ?? 00 00 0a 11 5b 17 d6 13 5b 11 5b 11 5d 31 da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBAB_2147838482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBAB!MTB"
        threat_id = "2147838482"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0a 00 06 7e ?? 00 00 04 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0b 07 02 28 ?? 00 00 0a 16 02 28 ?? 00 00 0a 8e 69 6f ?? 00 00 0a 0c 08 0d de 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_A_2147839036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.A!MTB"
        threat_id = "2147839036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 05 11 06 8f 5b 00 00 01 25 71 5b 00 00 01 11 06 0e 04 58 20 ff 00 00 00 5f d2 61 d2 81 5b 00 00 01 16 13 0e 11 06 17 58 13 06 1c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_A_2147839036_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.A!MTB"
        threat_id = "2147839036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 17 58 20 ff 00 00 00 5f 0c 09 11 07 08 91 58 20 ff 00 00 00 5f 0d 11 07 08 91 13 09 11 07 08 11 07 09 91 9c 11 07 09 11 09 9c 11 06 11 04 11 07 11 07 08 91 11 07 09 91 58 20 ff 00 00 00 5f 91 06 11 04 91 61 9c 11 04 17 58 13 04 11 04 11 0c 31 ad}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_A_2147839036_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.A!MTB"
        threat_id = "2147839036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 06 11 06 9a 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 11 06 17 d6 13 06 11 06 11 05 31}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 0a 0c 08 14 72 ?? ?? ?? 70 17 8d ?? 00 00 01 25 16 07 28 ?? 00 00 0a 28 ?? 00 00 0a a2 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 0d 09 14 72 ?? ?? ?? 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 11 04 14 72 ?? ?? ?? 70 18 8d ?? 00 00 01 25 16 72 ?? ?? ?? 70 a2 14 14 14 17 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBAU_2147841709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBAU!MTB"
        threat_id = "2147841709"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {c5 c6 b4 c6 f2 5d 28 c7 44 c5 44 c5 4c c7 44 c5 44 c5 44 c5 44 c5 59 c5 44 c5 44 c5 44 c5 44 c5 2f 00 2f 00 38 00 44 c5 44 c5 4d c7 e8}  //weight: 3, accuracy: High
        $x_3_2 = {d4 c6 0b 4e e8 5d 28 c7 44 c5 44 c5 44 c5 d4 c6 ba 4e 4c c5 e8 5d 44 c5 44 c5 48 c5 e5 5d e3 53 44 c5}  //weight: 3, accuracy: High
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "GetString" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBAW_2147841710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBAW!MTB"
        threat_id = "2147841710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 7e [0-32] 0a 00 08 18 6f ?? 00 00 0a 00 28 ?? 00 00 0a 08 6f ?? 00 00 0a 07 16 07 8e b7 6f 6d 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {23 06 2d 06 46 06 2d 06 44 06 2c 06 48 06 46 06 2e 06 46 06 46 06 48 06 2c 06 31 06 23 06 43 06 43 06 46 06 43 06 31 06 31 06 2c 06 46 06 31 06 31 06 31 06 44 06 2d 06 31 06 2f 06 31}  //weight: 1, accuracy: High
        $x_1_3 = "b5f26be103b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBBC_2147841721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBBC!MTB"
        threat_id = "2147841721"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 07 09 16 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 09 17 d6 0d 09 08 31 dd}  //weight: 1, accuracy: Low
        $x_1_2 = "0cd7fa61d04d" ascii //weight: 1
        $x_1_3 = "linkpicture.com/q/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBBG_2147841733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBBG!MTB"
        threat_id = "2147841733"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 00 30 00 30 00 30 00 30 00 00 84 b1 54 00 41 00 5a 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 51 00 41 00 41 00 42 00 41 00 41 00 67 00 42 00 41 00 73 00 41 00 51 00 41 00 41 00 41 00 41 00 4b 00 6f 00 41 00 59 00 41}  //weight: 2, accuracy: High
        $x_2_2 = "ARARAAiGAKhSAqArTaAAQhwAxEQynAhR" wide //weight: 2
        $x_1_3 = "EntryPoint" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBBL_2147841888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBBL!MTB"
        threat_id = "2147841888"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TAAAAAAAAAAAAAAAgA4NTGBnImByaE1uJABAAmAAA" wide //weight: 1
        $x_1_2 = "KKAEAHiUlAEoBbmASAGpAEAAAARITFhV" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBBN_2147841890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBBN!MTB"
        threat_id = "2147841890"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 36 62 01 70 17 18 8d ?? 00 00 01 0d 09 16 72 44 62 01 70 a2 00 09 17 14 a2 00 09}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 06 72 2c 62 01 70 72 32 62 01 70 17 15 16}  //weight: 1, accuracy: High
        $x_1_3 = "TVqQ%^%^M%^%^%^%^E%" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBBO_2147841901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBBO!MTB"
        threat_id = "2147841901"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 00 30 00 30 00 30 00 30 00 00 84 99 54 00 54 00 41 00 41 00 41 00 41 00 41 00 41 00 48 00 41 00 44 00 66 00 4b 00 41 00 41 00 4d 00 41 00 41 00 41 00 4b 00 63 00 43 00 41 00 41 00 43 00 45 00 42}  //weight: 1, accuracy: High
        $x_1_2 = "QhLAA0AAovAAALcAoKMArZEEjycKWUvFoAZ" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBBP_2147841902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBBP!MTB"
        threat_id = "2147841902"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 11 05 11 06 20 00 00 00 00 11 06 8e b7 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 08 13 07 de 0e}  //weight: 1, accuracy: Low
        $x_1_2 = "C0YOVS9BuC9BqVSN3tjXAUmH1PbN0HD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBBE_2147842119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBBE!MTB"
        threat_id = "2147842119"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DSSx5SNN1V3VVx4PhwIeu/bBNdIT8n" wide //weight: 1
        $x_1_2 = "Borc9riNqTvO00+WB9MHFV" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBCO_2147843661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBCO!MTB"
        threat_id = "2147843661"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 04 46 04 46 04 56 04 56 04 4b 04 41 04 3a 04 4f 04 56 04 56 04 46 04 3e 04 4b 04 36 04 30 04 32 04 56 04 4b 04 4b 04 56 04 45 04 3b 04 34 04 4b 04}  //weight: 1, accuracy: High
        $x_1_2 = "Pv7F2pUsDEmrwukSHrIRqiVIvfzkN3O9QKeVLAhx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_EH_2147843692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.EH!MTB"
        threat_id = "2147843692"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GFC7iN8FM" ascii //weight: 1
        $x_1_2 = "e53w34m968awCm9P85taUZe" ascii //weight: 1
        $x_1_3 = "explorer.Resources.resources" ascii //weight: 1
        $x_1_4 = "explorer.pdb" ascii //weight: 1
        $x_1_5 = "FtCx7BaL7VENRrrS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDN_2147844719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDN!MTB"
        threat_id = "2147844719"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fadd2518-442f-4f1a-b6d9-c23253ad2b50" ascii //weight: 1
        $x_1_2 = "NjPOD_Remastered" ascii //weight: 1
        $x_1_3 = "W82A28AWWC23W004A60B621W31D87B7227" ascii //weight: 1
        $x_1_4 = "N690E19BF0F3N162F46CC1N99FDNF53N32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDP_2147845668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDP!MTB"
        threat_id = "2147845668"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0e 06 4a 11 0d 06 4a 91 11 0c 06 4a 11 0c 8e 69 5d 91 61 d2 9c 00 06 06 4a 17 58 54}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDO_2147845692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDO!MTB"
        threat_id = "2147845692"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e61fd693-d5ed-4f22-a441-53a0e0d5262b" ascii //weight: 1
        $x_1_2 = "Vooly Nba" wide //weight: 1
        $x_2_3 = {fe 0c 05 00 fe 0c 06 00 8f 16 00 00 01 25 71 16 00 00 01 fe 0c 06 00 fe 09 04 00 58 20 ff 00 00 00 5f d2 61 d2 81 16 00 00 01 20 14 00 00 00 fe 0e 12 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBCC_2147845797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBCC!MTB"
        threat_id = "2147845797"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PqQLBZ94lEHFwUiole7y6Yy4X" wide //weight: 1
        $x_1_2 = "+LNrXpRkL5kgt3MrvCATKng/x7iEEyO3xBd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBCC_2147845797_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBCC!MTB"
        threat_id = "2147845797"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "TUrpZEoTh6eHPSVtz9mkeVHv1OEQMZ5Y1" wide //weight: 5
        $x_5_2 = "QtkELP7qGrLx34BNbdWDxswdR4a" wide //weight: 5
        $x_1_3 = "RijnDecrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBCD_2147845836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBCD!MTB"
        threat_id = "2147845836"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 08 16 73 ?? 00 00 0a 13 05 11 05 09 16 09 8e b7 6f 3d 00 00 0a 26 de 0c}  //weight: 1, accuracy: Low
        $x_1_2 = "ad0a90f0-ad58-4e5b-8577-14cf4703d3d3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBCV_2147846808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBCV!MTB"
        threat_id = "2147846808"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TQAIdJAfBAAAAAAChAALAAKAAAFAAB" wide //weight: 1
        $x_1_2 = {56 00 41 00 41 00 62 00 43 00 41 00 41 00 6f 00 41 00 41 00 41 00 4b 00 4d 00 41 00 41 00 43 00 47 00 41 00 41 00 6e 00 41 00 41 00 46 00 41 00 41 00 41 00 49 00 41 00 51 00 41 00 6a 00 6f 00 41 00 42 00 41 00 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBCE_2147847399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBCE!MTB"
        threat_id = "2147847399"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 03 08 17 28 ?? 00 00 0a 28 ?? 00 00 0a 61 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 08 17 58 b5 0c 08 11 04 13 05 11 05 31 d1}  //weight: 1, accuracy: Low
        $x_1_2 = "a891-6116232b3f65" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDS_2147851647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDS!MTB"
        threat_id = "2147851647"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "9d6b7342-150e-4ef4-9196-e47291d64384" ascii //weight: 1
        $x_1_2 = "NMKXhDKT2fwjcSwLeP" ascii //weight: 1
        $x_1_3 = "Xw6OmhI83VVfK37Guw" ascii //weight: 1
        $x_1_4 = "usa crypt file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDR_2147851685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDR!MTB"
        threat_id = "2147851685"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "26a07ac9-c05d-4740-8b22-af7bf7b463e7" ascii //weight: 1
        $x_1_2 = "ProcessAndRegVal" ascii //weight: 1
        $x_1_3 = "ProcessOnly_CorrM_Hider" ascii //weight: 1
        $x_1_4 = "ProcessOnly CorrM Hider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_MBHF_2147851805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.MBHF!MTB"
        threat_id = "2147851805"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 0a 03 09 03 28 ?? 00 00 0a 6a 5d 17 6a 58 69 17 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 11 04 06 07 61 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 09 17 6a 58 0d 09 11 06 31 a5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_AMAA_2147890317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.AMAA!MTB"
        threat_id = "2147890317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 07 6f 0b 00 00 0a 00 08 18 6f ?? 00 00 0a 00 08 18 6f ?? 00 00 0a 00 08 6f ?? 00 00 0a 0d 09 06 16 06 8e 69 6f ?? 00 00 0a 13 04 08 6f ?? 00 00 0a 00 28 ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 2b 00 11 05 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "RijndaelManaged" ascii //weight: 1
        $x_1_3 = "BJPRV4BM" ascii //weight: 1
        $x_1_4 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDW_2147896259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDW!MTB"
        threat_id = "2147896259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encryption Server" ascii //weight: 1
        $x_1_2 = "mKFGIOZWZXLEACZPNCEBPF" ascii //weight: 1
        $x_1_3 = "mNEAPDTDIJGTBJFAR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDX_2147898467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDX!MTB"
        threat_id = "2147898467"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 11 05 02 11 05 91 11 04 61 08 07 91 61 b4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDY_2147898628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDY!MTB"
        threat_id = "2147898628"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {17 28 07 00 00 0a 7e 04 00 00 04 28 08 00 00 0a 26}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDZ_2147898713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDZ!MTB"
        threat_id = "2147898713"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gfhhj" ascii //weight: 1
        $x_1_2 = "a0ep6a15HuHbCqBz" ascii //weight: 1
        $x_1_3 = "a8YFyRECMbZy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDV_2147899040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDV!MTB"
        threat_id = "2147899040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0c 02 28 46 00 00 0a 0d 09 8e 69 08 8e 69 59}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_LL_2147900443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.LL!MTB"
        threat_id = "2147900443"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 11 05 02 11 05 91 08 11 05 09 5d 91 61 9c 00 2b 06 9c ?? ?? ?? ?? ?? 11 05 17 d6 13 05 2b 06 9c ?? ?? ?? ?? ?? 11 05 11 08 31 02 2b 09 2b 99 13 07}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDAA_2147902906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDAA!MTB"
        threat_id = "2147902906"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1d 13 0d 11 06 28 ?? ?? ?? ?? 16 fe 02 13 0e 11 0e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_NH_2147909862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.NH!MTB"
        threat_id = "2147909862"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 11 07 08 11 07 6f ?? 00 00 0a 11 05 11 07 02 58 11 06 5d 93 61 d1 d1 9d 17 11 07 58 13 07 19}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_NI_2147910552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.NI!MTB"
        threat_id = "2147910552"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {26 16 02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e ?? 00 00 04 0e 06 17 59 95 58 0e 05}  //weight: 5, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 1
        $x_1_3 = "taskkill /IM" ascii //weight: 1
        $x_1_4 = "get_AllowOnlyFipsAlgorithms" ascii //weight: 1
        $x_1_5 = "System.Security.Cryptography.CryptoConfig" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_NJ_2147913057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.NJ!MTB"
        threat_id = "2147913057"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1a 13 09}  //weight: 5, accuracy: High
        $x_2_2 = "get_UseSystemPasswordChar" ascii //weight: 2
        $x_2_3 = "4c492b45-3dde-428f-9b26-e366b38fa0cf" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_RDAC_2147925435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.RDAC!MTB"
        threat_id = "2147925435"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 80 02 01 00 04 28 0d 00 00 2b fe 0c 00 00 fe 06 fa 00 00 06 73 d0 00 00 0a 28 0e 00 00 2b 28 0f 00 00 2b fe 0e 02 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_njRAT_NAK_2147928691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/njRAT.NAK!MTB"
        threat_id = "2147928691"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "njRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "c0a9a70f-63e8-42ca-965d-73a1bc903e62" ascii //weight: 2
        $x_1_2 = "NJRAT.FURL.resources" ascii //weight: 1
        $x_1_3 = "NJRAT.Pass.resources" ascii //weight: 1
        $x_1_4 = "NJRAT.script.resources" ascii //weight: 1
        $x_1_5 = {4e 00 4a 00 52 00 41 00 54 00 5c 00 6f 00 62 00 6a 00 5c 00 44 00 65 00 62 00 75 00 67 00 5c 00 [0-31] 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_6 = {4e 4a 52 41 54 5c 6f 62 6a 5c 44 65 62 75 67 5c [0-31] 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

