rule Trojan_MSIL_DCRat_SK_2147755309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.SK!MTB"
        threat_id = "2147755309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "*.dclib" wide //weight: 5
        $x_5_2 = "DCRatPlugin" wide //weight: 5
        $x_5_3 = "##################-DCRat-##################" wide //weight: 5
        $x_5_4 = "DCRat.Code" wide //weight: 5
        $x_1_5 = "DCRatBuild.exe" ascii //weight: 1
        $x_1_6 = "DCRatBuild.Visitors" ascii //weight: 1
        $x_1_7 = "DCRatBuild.Configurations" ascii //weight: 1
        $x_1_8 = "DCRatBuild.Dictionaries" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_DCRat_DEN_2147810489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.DEN!MTB"
        threat_id = "2147810489"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\discord\\Local Storage\\leveldb" ascii //weight: 3
        $x_3_2 = "OnStealerDone" ascii //weight: 3
        $x_3_3 = "Work.log" ascii //weight: 3
        $x_3_4 = "SELECT * FROM FirewallProduct" ascii //weight: 3
        $x_3_5 = "{11111-22222-10009-11112}" ascii //weight: 3
        $x_3_6 = "ZGKiHslGPo6vWnIjal.y9LylEaSct3rSferV0" ascii //weight: 3
        $x_3_7 = "{11111-22222-50001-00000}" ascii //weight: 3
        $x_3_8 = "root\\SecurityCenter" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_EW_2147814253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.EW!MTB"
        threat_id = "2147814253"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {01 57 ff 03 3e 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 38 01 00 00 32 01 00 00 bb 04 00 00 49 0f}  //weight: 3, accuracy: High
        $x_3_2 = "x5E0awbitEqjSDmgDX.oN8Qlsvu43PVCqLX8G" ascii //weight: 3
        $x_3_3 = "{11111-22222-50001-00000}" ascii //weight: 3
        $x_3_4 = "GetDelegateForFunctionPointer" ascii //weight: 3
        $x_3_5 = "2020.4.11.16511847" ascii //weight: 3
        $x_3_6 = "System.Security.Cryptography.AesCryptoServiceProvider" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_EC_2147814254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.EC!MTB"
        threat_id = "2147814254"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "System.Security.Cryptography.AesCryptoServiceProvider" ascii //weight: 3
        $x_3_2 = "{11111-22222-10009-11112}" ascii //weight: 3
        $x_3_3 = "BHxqwq8oyu12VhypWS.fueOfykw4Q0JxKbAk1" ascii //weight: 3
        $x_3_4 = "{11111-22222-50001-00000}" ascii //weight: 3
        $x_3_5 = "GetDelegateForFunctionPointer" ascii //weight: 3
        $x_3_6 = "2020.4.11f1_fbf367ac14e9" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_AW_2147816631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.AW!MTB"
        threat_id = "2147816631"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {01 57 ff 03 3e 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 31 01 00 00 31 01 00 00 c9 04 00 00 46 0f}  //weight: 3, accuracy: High
        $x_3_2 = "DirectorySeparatorChar" ascii //weight: 3
        $x_3_3 = "System.Text.RegularExpressions" ascii //weight: 3
        $x_3_4 = "Rfc2898DeriveBytes" ascii //weight: 3
        $x_3_5 = "{11111-22222-20001-00001}" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_A_2147825238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.A!MTB"
        threat_id = "2147825238"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 3b 00 00 01 13 07 09 28 a8 01 00 0a 16 11 07 16 1a ?? ?? ?? ?? ?? 11 04 28 a8 01 00 0a 16 11 07 1a 1a ?? ?? ?? ?? ?? 11 05 28 a8 01 00 0a 16 11 07 1e 1a ?? ?? ?? ?? ?? 11 06 28 a8 01 00 0a 16 11 07 1f 0c 1a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_AN_2147830116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.AN!MTB"
        threat_id = "2147830116"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6e 00 6f 00 6d 00 69 00 6e 00 61 00 6c 00 6c 00 79 00 2e 00 72 00 75 00 2f 00 65 00 78 00 65 00 63 00 2f 00 [0-48] 2e 00 74 00 78 00 74 00}  //weight: 5, accuracy: Low
        $x_1_2 = "lqFmcqeyPOiSReHLMfflRkQKlEwmjgfHCVApKdxu" wide //weight: 1
        $x_1_3 = "QRdOPqSPUFmpIOIgehfhnyxMfTALVAukRjwyAPivTWbHcNFcKxVvSndS" wide //weight: 1
        $x_1_4 = "yyvHLOTwiSTYjpTfhWSptmwjxpjgzimmOHFvHsFoojRDsPuDxByAkFdMBMJVfmwzfgJcj" wide //weight: 1
        $x_1_5 = "WGhiUVqfuozEXhypuHlaEsPlfzCxUkNyWfwOvANZuMzTIeMtQVBjTXydqwDVTsKJb" wide //weight: 1
        $x_1_6 = "rO7bH9h2.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_ABBN_2147834312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.ABBN!MTB"
        threat_id = "2147834312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 17 58 0a 06 20 ?? ?? ?? 00 5d 0a 08 11 06 06 94 58 0c 08 20 ?? ?? ?? 00 5d 0c 11 06 06 94 13 04 11 06 06 11 06 08 94 9e 11 06 08 11 04 9e 11 06 11 06 06 94 11 06 08 94 58 20 ?? ?? ?? 00 5d 94 0d 11 07 07 03 07 91 09 61 d2 9c 2b 07 13 07 38 ?? ?? ?? ff 07 17 58 0b 2b 07 13 06}  //weight: 3, accuracy: Low
        $x_1_2 = "DLqHt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_MBS_2147838055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.MBS!MTB"
        threat_id = "2147838055"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TVqQ()()M()()()()E()()()()//8()" wide //weight: 1
        $x_1_2 = "mdlZD5iX181Xz()()PHJpY2hUZXh0Qm" wide //weight: 1
        $x_1_3 = "PX00001" ascii //weight: 1
        $x_1_4 = "PX00004" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_MBH_2147838094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.MBH!MTB"
        threat_id = "2147838094"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 00 00 fe 0c 01 00 fe 0c 00 00 fe 0c 01 00 93 20 ef 9d 0d 2e 20 36 db 6c 26 61 20 5c bc e6 dc 58 20 ad 91 18 fc 59 20 ca 71 2f e9 61 20 07 00 00 00 62 20 06 00 00 00 63 61 d1 9d}  //weight: 1, accuracy: High
        $x_1_2 = {38 33 38 32 30 34 32 33 36 00 3c 4d 6f 64 75 6c 65 3e 00 74 50 43 6b 46}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_MBC_2147838129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.MBC!MTB"
        threat_id = "2147838129"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TgFRVzgHYamh5hqQjJt3K" ascii //weight: 1
        $x_1_2 = "ZVbMBux6QdnMrtHT312LXdyu6bkECGBjiQGhBtwWvw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_SPAN_2147840305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.SPAN!MTB"
        threat_id = "2147840305"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 16 9a 17 8d ?? ?? ?? 01 13 18 11 18 16 1f 20 9d 11 18 6f ?? ?? ?? 0a 13 10 de 03}  //weight: 2, accuracy: Low
        $x_1_2 = "7wkHjueQJkFxNvEUWPOHEA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_MBAP_2147840414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.MBAP!MTB"
        threat_id = "2147840414"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 16 07 17 94 17 da 17 d6 8d ?? 00 00 01 a2 25 17 28 ?? 01 00 0a 06 16 1e 6f ?? 01 00 0a 6f ?? 01 00 0a a2 25}  //weight: 1, accuracy: Low
        $x_1_2 = "i.ibb.co/3RGKh7p" wide //weight: 1
        $x_1_3 = "a-696781e46846" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_DA_2147841383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.DA!MTB"
        threat_id = "2147841383"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {18 2d 26 26 28 ?? 00 00 0a 07 6f ?? 00 00 0a 72 ?? 00 00 70 7e ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 1d 2d 06 26 de 13 0b 2b d8 0c 2b f8 26 de 00 06 17 58 0a 06 1b 32 c0}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_AD_2147841502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.AD!MTB"
        threat_id = "2147841502"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 2d 07 15 2c 04 2b 4d 2b 52 1c 2c 31 16 2b 4f 2b 2c 2b 4e 2b 4f 72 ?? ?? ?? 70 2b 4f 2b 54 2b 55 72 ?? ?? ?? 70 2b 55 8e 69 5d 91 7e ?? ?? ?? 04 07 91 61 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_C_2147841507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.C!MTB"
        threat_id = "2147841507"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 06 0b 07 28 04 00 00 0a 20 ?? 00 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 7d ?? 00 00 04 07 fe}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 0a 20 00 00 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 0a 06 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_DB_2147841531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.DB!MTB"
        threat_id = "2147841531"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b 3f 0a 2b fb 00 28 ?? 00 00 06 1a 2d 26 26 28 ?? 00 00 0a 07 6f ?? 00 00 0a 72 ?? 00 00 70 7e ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 16 2c 06 26 de 13 0b 2b d8 0c 2b f8 26 de 00 06 17 58 0a 06 1b 32 c0}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_ADR_2147841950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.ADR!MTB"
        threat_id = "2147841950"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 fe 01 0a 06 2c 41 00 7e 59 00 00 0a 0b 00 28 cc 00 00 0a 6f cd 00 00 0a 6f ce 00 00 0a 0b 00 de 05 26 00 00 de 00 07 28 0c 00 00 0a 0c 08 2c 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_ADR_2147841950_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.ADR!MTB"
        threat_id = "2147841950"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 16 13 04 2b 29 07 06 08 16 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 05 12 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 11 04 17 58 13 04 11 04 09 fe 04 13 06 11 06 2d cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_ADA_2147842668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.ADA!MTB"
        threat_id = "2147842668"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {14 fe 03 0b 07 2c 54 00 02 7b 0b 00 00 04 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 02 7b 0c 00 00 04 06 6f ?? ?? ?? 0a 0c 12 02 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 02 7b 0d 00 00 04 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 02 7b 0e 00 00 04 06 6f ?? ?? ?? 0a 17 59 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "Veresiye.UI.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_MA_2147843994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.MA!MTB"
        threat_id = "2147843994"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 00 04 61 28 ?? 0d 00 06 73 ?? 01 00 06 28 ?? 01 00 06}  //weight: 1, accuracy: Low
        $x_10_2 = "VisualStudio.Shell.Framework.dll" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_MA_2147843994_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.MA!MTB"
        threat_id = "2147843994"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Fvl0cAfbhl2Z96jqqtCVgiR4OKkgr2GtK" ascii //weight: 20
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_4 = "schtasks.exe /delete /tn" wide //weight: 1
        $x_1_5 = "DCRat.Code" wide //weight: 1
        $x_1_6 = {57 ff b7 3f 09 1e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 22 01 00 00 0a 01 00 00 52 05 00 00 7a 06 00 00 43 00 00 00 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_MBCZ_2147844455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.MBCZ!MTB"
        threat_id = "2147844455"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 0c 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 06 09 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = "27PSgncGpwYBh6ukWtTVu9uz0oJ" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_EAP_2147844571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.EAP!MTB"
        threat_id = "2147844571"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0c 16 13 05 2b 1c 00 08 11 05 07 11 05 9a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d d7}  //weight: 3, accuracy: Low
        $x_2_2 = "WQJzjw.Properties.Resources" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_FAI_2147845942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.FAI!MTB"
        threat_id = "2147845942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 16 0b 2b 31 7e ?? 05 00 04 06 7e ?? 06 00 04 02 07 6f ?? 00 00 0a 7e ?? 05 00 04 07 7e ?? 05 00 04 8e 69 5d 91 61 28 ?? 0b 00 06 28 ?? 06 00 06 26 07 17 58 0b 07 02 6f c7 00 00 0a 32 c6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_RDB_2147846141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.RDB!MTB"
        threat_id = "2147846141"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DCRatLoader" ascii //weight: 1
        $x_2_2 = {09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_B_2147846913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.B!MTB"
        threat_id = "2147846913"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 04 07 06 6f ?? 00 00 0a 28 ?? 00 00 0a 0d 28 ?? 00 00 0a 09 16 09 8e 69 6f ?? 00 00 0a 28 ?? 00 00 0a 13 04 7e}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 0a 18 33 2e 09 6f ?? 00 00 0a 16 6a 31 08 09 6f ?? 00 00 0a 2d 02 de 26 02 09 6f ?? 00 00 0a 06 7b ?? 00 00 04 06 7b ?? 00 00 04 16 2c 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_NTY_2147847506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.NTY!MTB"
        threat_id = "2147847506"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 04 00 00 06 28 ?? ?? ?? 2b 74 ?? ?? ?? 01 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "Qrlydcszoo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_PSOV_2147847860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.PSOV!MTB"
        threat_id = "2147847860"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 72 23 00 00 70 14 d0 02 00 00 02 28 14 00 00 0a 18 8d 31 00 00 01 25 16 16 14 28 18 00 00 0a a2 25 17 17 14 28 18 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_F_2147848663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.F!MTB"
        threat_id = "2147848663"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "xUukrb" wide //weight: 2
        $x_2_2 = "FtOHK.g.resources" ascii //weight: 2
        $x_2_3 = "Invoke" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_JB_2147848674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.JB"
        threat_id = "2147848674"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "250"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "ICBfX18gICAgICAgICAgIF8gICAgICBfX18gICAgICAgICAgICAgXyAgICAgICAgXyAgIF9fXyAgICBfIF9fX19fIA0" wide //weight: 50
        $x_50_2 = "Failed to load the plugin" wide //weight: 50
        $x_50_3 = "Plugin couldn't process this action!" wide //weight: 50
        $x_50_4 = "Unknown command! Maybe a plugin is required?" wide //weight: 50
        $x_50_5 = "DCRat.Code" wide //weight: 50
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_AADL_2147849891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.AADL!MTB"
        threat_id = "2147849891"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 26 0b 16 28 ?? 00 00 06 0c 2b 1e 06 08 06 08 91 07 08 07 28 ?? 01 00 06 25 26 69 5d 91 61 d2 9c 08 1a 28 ?? 00 00 06 58 0c 08 06 28 ?? 01 00 06 25 26 69 32 d6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_CXLM_2147849969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.CXLM!MTB"
        threat_id = "2147849969"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DcRatByqwqdanchun" wide //weight: 1
        $x_1_2 = "Anti_virus" wide //weight: 1
        $x_1_3 = "Select * from AntivirusProduct" wide //weight: 1
        $x_1_4 = "SELECT * FROM Win32_OperatingSystem WHERE Primary='true'" wide //weight: 1
        $x_1_5 = "SELECT * FROM Win32_Processor" wide //weight: 1
        $x_1_6 = "Select * From Win32_ComputerSystem" wide //weight: 1
        $x_1_7 = "SELECT * FROM Win32_DisplayConfiguration" wide //weight: 1
        $x_1_8 = "CountryCode" wide //weight: 1
        $x_1_9 = "Camera" wide //weight: 1
        $x_1_10 = "LastBootUpTime" wide //weight: 1
        $x_1_11 = "TotalPhysicalMemory" wide //weight: 1
        $x_1_12 = "Paste_bin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_AADN_2147849970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.AADN!MTB"
        threat_id = "2147849970"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 01 02 7b ?? 00 00 04 6f ?? 00 00 0a 38 ?? 00 00 00 11 00 11 01 6f ?? 00 00 0a 16 73 ?? 00 00 0a 13 06}  //weight: 2, accuracy: Low
        $x_2_2 = {11 0a 16 11 08 16 11 08 8e 69 28 ?? 00 00 0a 38 00 00 00 00 11 08 13 09 38 ?? 00 00 00 11 06 11 0a 16 11 0a 8e 69 28 ?? 00 00 06 8d ?? 00 00 01 13 08 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_AADQ_2147849990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.AADQ!MTB"
        threat_id = "2147849990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 72 0d 00 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 0a dd ?? 00 00 00 26 dd 00 00 00 00 06 2c d1}  //weight: 2, accuracy: Low
        $x_1_2 = "80.66.89.93" wide //weight: 1
        $x_1_3 = "ReadAsByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_CXFW_2147850214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.CXFW!MTB"
        threat_id = "2147850214"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 07 6f 21 00 00 0a 03 07 03 6f ?? ?? ?? ?? 5d 6f ?? ?? ?? ?? 61 d1 0c 06 08 6f ?? ?? ?? ?? 26 07 17 58 0b 07 02 6f ?? ?? ?? ?? 32 d3}  //weight: 1, accuracy: Low
        $x_1_2 = "aHyPYif8LaEoh83NWXWYQud6tq1XY4eCsUscMDxCj/w=" wide //weight: 1
        $x_1_3 = "pTP2Nf/rJk+yO4zTrQqEPQ==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_RDC_2147850259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.RDC!MTB"
        threat_id = "2147850259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "18BWp756taIcThf6PpptW04AyCaEYEkd9rsjQbXIasfB" ascii //weight: 1
        $x_1_2 = "ITtHwcBPsU5ZbXGmla" ascii //weight: 1
        $x_1_3 = "7pBHFtCpl6Qim4IuXo" ascii //weight: 1
        $x_1_4 = "lSfgApatkdxsVcGcrktoFd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_AAEK_2147850280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.AAEK!MTB"
        threat_id = "2147850280"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 06 16 73 ?? 00 00 0a 0b 16 0c 00 0f 00 08 20 00 04 00 00 58 28 ?? 00 00 2b 00 07 02 08 20 00 04 00 00 6f ?? 00 00 0a 0d 08 09 58 0c 00 09 20 00 04 00 00 fe 04 16 fe 01 13 04 11 04 2d cc}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_G_2147851176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.G!MTB"
        threat_id = "2147851176"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/c Shutdown /r /f /t" wide //weight: 2
        $x_2_2 = {57 ff b7 3f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 4b 01 00 00 26 06 00 00 3c 06 00 00 b5 0e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_AAGO_2147851310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.AAGO!MTB"
        threat_id = "2147851310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 20 80 00 00 00 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 17 6f ?? 00 00 0a 06 03 6f ?? 00 00 0a 06 04 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 02 07 28 ?? 00 00 06 0c de 14 07 2c 06 07 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
        $x_1_2 = "fRZstgVonklWpSLeb9ZKcoDkGPzHwDqSAMyTxoopGcb=" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_PSTG_2147851665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.PSTG!MTB"
        threat_id = "2147851665"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 0c 00 00 0a 13 05 11 04 8d 08 00 00 01 13 06 11 05 11 06 16 11 04 6f 0a 00 00 0a 26 11 06 13 07 dd 1c 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_AAHO_2147851712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.AAHO!MTB"
        threat_id = "2147851712"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {fe 0c 01 00 fe 0c 02 00 fe 09 00 00 fe 0c 02 00 91 fe 0c 00 00 fe 0c 02 00 fe 0c 00 00 8e 69 5d 91 61 d2 9c fe 0c 02 00 20 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 09 00 00 8e 69 3f}  //weight: 4, accuracy: High
        $x_1_2 = "2GM23j301t60Z96T" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_NDE_2147852196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.NDE!MTB"
        threat_id = "2147852196"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 18 00 00 06 00 28 ?? ?? 00 0a 72 ?? ?? 00 70 28 ?? ?? 00 0a 6f ?? ?? 00 0a 28 ?? ?? 00 0a 02 28 ?? ?? 00 0a 7e ?? ?? 00 04 15 16 28 ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "dGdsc3Bwc3hibGxwcG1x" wide //weight: 1
        $x_1_3 = "Alexander Roshal" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_RDD_2147852686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.RDD!MTB"
        threat_id = "2147852686"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bt1EZHJgfLaohDIS" ascii //weight: 1
        $x_1_2 = "jGVj2" ascii //weight: 1
        $x_1_3 = "LogicalConjunction" ascii //weight: 1
        $x_1_4 = "WhichTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_AAMH_2147888651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.AAMH!MTB"
        threat_id = "2147888651"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 29 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 02 28 ?? 00 00 06 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "nTOz2aV5mHQGFJ9hs6yIM2XFsxZzjzUgXXG0bRWhjIA=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_RDE_2147890117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.RDE!MTB"
        threat_id = "2147890117"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fe 0c 02 00 fe 0c 01 00 6f 79 03 00 0a 20 01 00 00 00 73 7a 03 00 0a 25 fe 0c 00 00 20 00 00 00 00 fe 0c 00 00 8e 69 6f 1d 00 00 0a 25 6f 7b 03 00 0a fe 0c 02 00 6f c8 01 00 0a fe 0e 00 00 fe 0c 02 00 6f 1e 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_I_2147891596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.I!MTB"
        threat_id = "2147891596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BRTAuTGNT1Pw92Zdt4.qv6JngBdgxY54VJRZN" wide //weight: 2
        $x_2_2 = "OdA2pZy4e" wide //weight: 2
        $x_1_3 = "DynamicInvoke" ascii //weight: 1
        $x_1_4 = "CreateDelegate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_DCRat_MAAB_2147891672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.MAAB!MTB"
        threat_id = "2147891672"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$d1cc2bad-d6f7-47b8-afa8-3a9d4430dcc1" ascii //weight: 10
        $x_10_2 = {57 9d 02 3c 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 5a 00 00}  //weight: 10, accuracy: High
        $x_1_3 = "ConfusedByAttribute" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "AesManaged" ascii //weight: 1
        $x_1_7 = "Cockos Incorporated" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_ADC_2147892338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.ADC!MTB"
        threat_id = "2147892338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 0b 16 0c 07 8e 69 17 59 0d 38 18 00 00 00 07 08 91 13 04 07 08 07 09 91 9c 07 09 11 04 9c 08 17 58 0c 09 17 59 0d 08 09 3f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_ADC_2147892338_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.ADC!MTB"
        threat_id = "2147892338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0d 07 09 16 11 05 6f 17 00 00 0a 26 16 13 06 2b 11 09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 32 e8}  //weight: 2, accuracy: High
        $x_1_2 = "DCRatLoader.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_ADC_2147892338_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.ADC!MTB"
        threat_id = "2147892338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 2b 24 2b 1c 2b 23 7b 02 00 00 04 1f 31 2b 1d 58 d1 2b 1c 26 2b 20 16 2d 02 17 58 16 2d e2 2b 19 2b 1a 1b 32 df 2a 0a 2b d9 02 2b da 06 2b e0 6f}  //weight: 1, accuracy: High
        $x_1_2 = {26 06 17 58 0a 06 18 32 ad 16 0b 1e 2c f7 07 18 5d 2d 10 02 7b 02 00 00 04 1f 58 6f ?? 00 00 0a 26 2b 0e 02 7b 02 00 00 04 1f 59 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_RDF_2147892592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.RDF!MTB"
        threat_id = "2147892592"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 18 6f 32 00 00 0a 06 6f 33 00 00 0a 0c 02 0d 08 09 16 09}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_AMAD_2147892664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.AMAD!MTB"
        threat_id = "2147892664"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 0c 06 08 16 1f 10 6f ?? 00 00 0a 26 07 08 6f ?? 01 00 0a 06 07 6f ?? 01 00 0a 16 73 ?? 01 00 0a 13 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_AMAA_2147892944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.AMAA!MTB"
        threat_id = "2147892944"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 0a 02 11 0a 91 03 11 0a 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 20 ?? 00 00 00 38 ?? ?? ff ff 11 04 13 0c 38 ?? ?? ff ff 11 05 11 00 fe 04 13 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_AAVD_2147895165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.AAVD!MTB"
        threat_id = "2147895165"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 06 18 28 ?? 01 00 06 7e ?? 00 00 04 06 19 28 ?? 01 00 06 7e ?? 00 00 04 06 28 ?? 01 00 06 0d 7e ?? 00 00 04 09 02 16 02 8e 69 28 ?? 01 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_RDG_2147895396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.RDG!MTB"
        threat_id = "2147895396"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 14 11 15 11 13 11 15 9a 28 0e 00 00 0a 9c 11 15 17 58 13 15 11 15 11 13 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_RDH_2147895402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.RDH!MTB"
        threat_id = "2147895402"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 02 16 02 8e 69 6f 28 00 00 0a 00 07 6f 29 00 00 0a 00 06 6f 2a 00 00 0a 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_RDJ_2147897646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.RDJ!MTB"
        threat_id = "2147897646"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SGxDUr5uRrbW2X9YcTIdUkMi5E" ascii //weight: 1
        $x_1_2 = "pxqDsBPmp0nY" ascii //weight: 1
        $x_1_3 = "$TR$4E" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_RPZ_2147898289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.RPZ!MTB"
        threat_id = "2147898289"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 11 06 1f 16 5d 91 13 0d 11 0c 11 0d 61 13 0e 11 0e 11 0b 59 13 0f 07 11 09 11 0f 11 07 5d d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_RDK_2147898818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.RDK!MTB"
        threat_id = "2147898818"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 0f 01 00 06 28 12 01 00 06 74 22 00 00 01 0a 73 dd 00 00 0a 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_RDL_2147898993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.RDL!MTB"
        threat_id = "2147898993"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fortnite_loader" ascii //weight: 1
        $x_1_2 = "fn_loader" ascii //weight: 1
        $x_1_3 = "AppleCheats" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_PSFJ_2147899366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.PSFJ!MTB"
        threat_id = "2147899366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 3c 00 00 0a 26 73 ?? ?? ?? 0a 13 0b 73 ?? ?? ?? 0a 13 0c 28 ?? ?? ?? 0a 11 06 6f ?? ?? ?? 0a 13 0d 11 0c 11 0d 16 11 0d 8e 69 73 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 0b 72 ?? ?? ?? 70 72 ?? ?? ?? 70 28 ?? ?? ?? 06 72 ?? ?? ?? 70 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 11 0c 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 0b 6f ?? ?? ?? 0a de 0c}  //weight: 5, accuracy: Low
        $x_1_2 = "DebuggingModes" ascii //weight: 1
        $x_1_3 = "NewLateBinding" ascii //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
        $x_1_5 = "HttpMessageInvoker" ascii //weight: 1
        $x_1_6 = "GetNetworkInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_CDC_2147899458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.CDC!MTB"
        threat_id = "2147899458"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 07 00 00 0a 11 00 28 ?? ?? ?? 06 13 06 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 39 ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff 73 ?? ?? ?? 0a 13 02 20 ?? ?? ?? 00}  //weight: 5, accuracy: Low
        $x_1_2 = "Ingjqgvfofy.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_NDT_2147900114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.NDT!MTB"
        threat_id = "2147900114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 d5 15 65 bb 65 20 ?? ?? ?? 35 61 7e a0 09 00 04 7b ?? ?? ?? 04 61 28 f9 0d 00 06 73 ?? ?? ?? 06 28 55 01 00 06 20 ?? ?? ?? 00 7e a0 09 00 04 7b ?? ?? ?? 04 39 69 ff ff ff 26 20 ?? ?? ?? 00 38 5e ff ff ff 14 38 ?? ?? ?? 00 38 4a 00 00 00 00 73 ?? ?? ?? 06 26 20 01 00 00 00 7e ?? ?? ?? 04 7b b1 09 00 04 3a ?? ?? ?? ff 26 20 00 00 00 00 38 ?? ?? ?? ff 28 0f 0f 00 06}  //weight: 5, accuracy: Low
        $x_1_2 = "p91naAPJ3ftIdgWgHn.eIcV1J10NMXHttmQkC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_J_2147900129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.J!MTB"
        threat_id = "2147900129"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 09 20 ff 00 00 00 9c 09 17 58 0d 09 08 8e 69 32}  //weight: 2, accuracy: High
        $x_2_2 = {25 17 58 13 0a 91 08 61 d2 9c 09 17 5f 17}  //weight: 2, accuracy: High
        $x_1_3 = "GetDelegateForFunctionPointer" ascii //weight: 1
        $x_1_4 = "get_EntryPoint" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_RDM_2147900170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.RDM!MTB"
        threat_id = "2147900170"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FVodu0kYNVZZ56GXoDG4sjRevFjsrsPWS7OySoti1G7D" ascii //weight: 1
        $x_1_2 = "kM8LLRGA94" ascii //weight: 1
        $x_1_3 = "oxZ2GcLov3VhQu2OGBY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_K_2147900186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.K!MTB"
        threat_id = "2147900186"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 02 12 02 12 03 6f ?? 00 00 0a 09 8e 69 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 28 ?? 00 00 06 59 8d ?? 00 00 01 13 04 09 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 28 ?? 00 00 06 11 04 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 28 ?? 00 00 06 11 04 8e 69 28 ?? 00 00 0a 11 04 13 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_PTFC_2147900424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.PTFC!MTB"
        threat_id = "2147900424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 8d 3a 00 00 01 13 04 7e 99 08 00 04 02 1a 58 11 04 16 08 28 ?? 01 00 0a 28 ?? 01 00 0a 11 04 16 11 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_PTFL_2147900622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.PTFL!MTB"
        threat_id = "2147900622"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 23 00 00 0a 17 59 28 ?? 01 00 0a 16 7e a8 08 00 04 02 1a 28 ?? 01 00 0a 11 05 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_NN_2147900902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.NN!MTB"
        threat_id = "2147900902"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e a7 ?? ?? ?? 0e 06 17 59 95 58 0e 05 ?? ?? 0d 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_SG_2147901063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.SG!MTB"
        threat_id = "2147901063"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qwqdanchun.Properties.Resources.resources" ascii //weight: 1
        $x_1_2 = "get_Assembly" ascii //weight: 1
        $x_1_3 = "6f5245be-37ec-4cfb-8f6f-03ed38215d0a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_SPXZ_2147901117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.SPXZ!MTB"
        threat_id = "2147901117"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dxlztpWCTArBAzuYLSShSdngs8mmBAgkw8d17T0AbaeUILSdFl" wide //weight: 1
        $x_1_2 = "JbGAymEEOSHHFti5SOrpesEUdhaHyQzOZPOGp1uhX3qqzFiQeAylo" wide //weight: 1
        $x_1_3 = "p1kQtn2PJ1YAtRwvnFfNFoT8xi33A6X6y1dAEQxA6wGZVZ3mxqWgKAF" wide //weight: 1
        $x_1_4 = "DN47seDL3MFiLjmNuL2v1HoVODOGDWyEq46gklfXWbZx5VDCcpOiwRDdGH" wide //weight: 1
        $x_1_5 = "ng6lD8vHJrskZJjhpy6assV0PqMkJn9L9q4spCVzZmPaEk2FZytpnqSmFiX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_PTGW_2147901274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.PTGW!MTB"
        threat_id = "2147901274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 1d 00 00 0a 17 59 28 ?? 01 00 0a 16 7e a5 08 00 04 02 1a 28 ?? 01 00 0a 11 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_LA_2147901431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.LA!MTB"
        threat_id = "2147901431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e b5 08 00 04 0e 06 17 59 95 58 0e 05 28 ?? 0d 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_LA_2147901431_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.LA!MTB"
        threat_id = "2147901431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5f 95 61 54 11 12 11 15 1f 0f 5f 11 12 11 15 1f 0f 5f 95 11 08 25 1a 58 13 08 4b 61 ?? ?? ?? ?? ?? 58 9e 11 15 17 58 13 15 11 23 17 58}  //weight: 5, accuracy: Low
        $x_5_2 = {11 0b 16 95 11 1e 25 1a 58 13 1e 4b 61 11 0c 16 95 58 11 0d 16 95 11 0e 16 95 5a 58 13 21 11 0b}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_E_2147902267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.E!MTB"
        threat_id = "2147902267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff 11 03 7e ?? ?? 00 04 28 ?? ?? 00 06 73 ?? 00 00 0a 20 20 02 00 00 7e}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_NC_2147902273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.NC!MTB"
        threat_id = "2147902273"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e 9e 08 00 04 0e 06 17 59 95 58 0e 05 28 ?? 0d 00 06 58 54}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_NL_2147902544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.NL!MTB"
        threat_id = "2147902544"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e b6 08 ?? ?? 0e 06 17 59 95 58 0e 05}  //weight: 5, accuracy: Low
        $x_5_2 = {03 02 4b 03 05 5f 04 05 66 5f 60 58 0e 07 0e 04 95 58 7e b6 ?? ?? ?? 0e 06 17 59 95 58 0e 05 ?? ?? 0d 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_CCHT_2147902560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.CCHT!MTB"
        threat_id = "2147902560"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a2 25 1a 72 ?? ?? ?? ?? a2 25 1b 28 ?? 00 00 06 a2 25 1c 72 ?? ?? ?? ?? a2 25 1d 28 ?? 00 00 06 a2 25 1e 28 ?? 00 00 06 a2 28 ?? 00 00 0a 7d ?? ?? ?? ?? 16 06 7b ?? ?? ?? ?? 8e 69 28 ?? 00 00 0a 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_NF_2147903263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.NF!MTB"
        threat_id = "2147903263"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 04 61 05 61 58 0e 07 0e 04 95 58 7e b0 08 00 04 0e 06 17 59 95 58 0e 05 28 ?? 0d 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_NF_2147903263_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.NF!MTB"
        threat_id = "2147903263"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e ?? 08 00 04 0e 06 17 59 95 58 0e 05 28 04 0e 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_FRAA_2147903479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.FRAA!MTB"
        threat_id = "2147903479"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 05 2b 2f 06 07 17 8d ?? 00 00 01 25 16 11 05 8c ?? 00 00 01 03 28 ?? 00 00 0a a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 05 17 d6 13 05 11 05 11 04 31 cb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_PTJI_2147903595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.PTJI!MTB"
        threat_id = "2147903595"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2d 18 06 02 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 0a 06 28 ?? 00 00 0a 26 02 28 ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_NI_2147904305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.NI!MTB"
        threat_id = "2147904305"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1f 1f 5f 62 02 7b ab 01 00 04 17 91 ?? ?? 00 00 00 5f 61 02 7b b2 01 00 04 5f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_NA_2147904510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.NA!MTB"
        threat_id = "2147904510"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 00 11 00 17 61 5a 1e 63 d2 2a 02 ?? ?? 04 00 04 18 95 20 ff ff 00 00 5f d1 18 60 d1 13 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_NG_2147904511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.NG!MTB"
        threat_id = "2147904511"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 09 28 b1 ?? ?? 44 14 16 9a 26 16 2d f9 02 03 02 4b 03 04 61 05 61}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_NJ_2147904512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.NJ!MTB"
        threat_id = "2147904512"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e 9c 08 00 04 0e 06 17 59 95 58 0e 05 28 ?? 0d 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_NK_2147904793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.NK!MTB"
        threat_id = "2147904793"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 7b a4 02 00 04 03 04 61 20 ff 00 00 00 5f 95 03 1e 64 61 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_JQAA_2147906574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.JQAA!MTB"
        threat_id = "2147906574"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 91 07 08 07 8e 69 5d 1f ?? 58 1f ?? 58 1f ?? 59 91 61 03 08 20 ?? ?? 00 00 58 20 ?? ?? 00 00 59 03 8e 69 5d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_RDO_2147909034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.RDO!MTB"
        threat_id = "2147909034"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5d 94 13 0c 11 05 11 0a 02 11 0a 91 11 0c 61 28 ?? ?? ?? ?? 9c 11 0a 17 58 13 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_L_2147909820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.L!MTB"
        threat_id = "2147909820"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {58 03 06 1e 58 4b 61 54 06 4b 06 1a 58 4b 61 06 1e 58 4b 61 1e 06 4b 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_SPXG_2147915759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.SPXG!MTB"
        threat_id = "2147915759"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YRYpuOK33h3Iv3xmfo.TBC8XU5AL96GUo8htw" ascii //weight: 1
        $x_1_2 = "muel9jwYZZsixLNgC6.2xmOdSgAEH8u1RLSnf" ascii //weight: 1
        $x_1_3 = "System.Security.Cryptography.AesCryptoServiceProvider" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "GetDelegateForFunctionPointer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_NB_2147917918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.NB!MTB"
        threat_id = "2147917918"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e 82 04 00 04 0e 06 17 59 e0 95 58 0e 05 28 bf 11 00 06 58 54 2a}  //weight: 5, accuracy: High
        $x_1_2 = "RSACryptoServiceProvider" ascii //weight: 1
        $x_1_3 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_4 = "RijndaelManaged" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_TZAA_2147918828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.TZAA!MTB"
        threat_id = "2147918828"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {15 59 91 61 ?? 08 20 0c 02 00 00 58 20 0b 02 00 00 59 1b 59 1b 58 ?? 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_RDP_2147919403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.RDP!MTB"
        threat_id = "2147919403"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "a119f643-943f-4714-a159-19ab9218b0a9" ascii //weight: 2
        $x_1_2 = "EvilProgram" ascii //weight: 1
        $x_1_3 = "TransformInput" ascii //weight: 1
        $x_1_4 = "GetEncodedData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_SCAG_2147919936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.SCAG!MTB"
        threat_id = "2147919936"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "jluiR6INEsGUXyjwaS.LKSvsOfnqhRnCSdLh4" ascii //weight: 2
        $x_1_2 = "System.Security.Cryptography.AesCryptoServiceProvider" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "GetDelegateForFunctionPointer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_SPAG_2147920487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.SPAG!MTB"
        threat_id = "2147920487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Q9uica2a622InXT8Sx.4aYyTZRtX532xwliFI" ascii //weight: 2
        $x_1_2 = "System.Security.Cryptography.AesCryptoServiceProvider" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "GetDelegateForFunctionPointer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_SJKG_2147921755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.SJKG!MTB"
        threat_id = "2147921755"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "0ywRuctNsJTbkcJr0l.5XcA1kVBcXdCKURQ4I" ascii //weight: 2
        $x_1_2 = "RICeXVPBgP7ixj2PVV.hrtu5T0kVH0v5uqLUU" wide //weight: 1
        $x_1_3 = "System.Security.Cryptography.AesCryptoServiceProvider" wide //weight: 1
        $x_1_4 = "GetDelegateForFunctionPointer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_DF_2147923700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.DF!MTB"
        threat_id = "2147923700"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {11 0f 11 21 19 58 e0 91 1f 18 62 11 0f 11 21 18 58 e0 91 1f 10 62 60 11 0f 11 21 17 58 e0 91 1e 62 60 11 0f 11 21 e0 91 60 13 06 20 42 00 00 00 fe 0e 32 00 38 47 f4 ff ff}  //weight: 3, accuracy: High
        $x_3_2 = "Y3rxMnsPgYSWN7oILC" ascii //weight: 3
        $x_3_3 = "yt9ZjJ88BDZQbPA3Qa" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_ARA_2147925404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.ARA!MTB"
        threat_id = "2147925404"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[DRAT]" wide //weight: 2
        $x_2_2 = "GET_INFO" wide //weight: 2
        $x_2_3 = "SENT_INFO" wide //weight: 2
        $x_2_4 = "SENT_SMS" wide //weight: 2
        $x_2_5 = "SENT_DIS" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_NIT_2147926208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.NIT!MTB"
        threat_id = "2147926208"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 7e 55 00 00 0a 72 0f 03 00 70 17 6f ?? 00 00 0a 0a 06 02 16 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 00 00 de 1b}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 72 77 03 00 70 28 ?? 00 00 0a 0b 72 77 03 00 70 28 ?? 00 00 0a 00 de 15 26 00 00 de 00 20 d0 07 00 00 28 ?? 00 00 0a 00 00 17 0c 2b d1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_DCRat_ND_2147928803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.ND!MTB"
        threat_id = "2147928803"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 25 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 07 28 ?? 00 00 0a 00 07}  //weight: 2, accuracy: Low
        $x_3_2 = {72 8d 00 00 70 28 ?? 00 00 0a 00 20 ?? 0d 00 00 28 ?? 00 00 0a 00 28}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_ND_2147928803_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.ND!MTB"
        threat_id = "2147928803"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TessaLetMeDie601Violet.jnfvqq" ascii //weight: 2
        $x_1_2 = "share lazy jump blue database vision understand you grow dark" ascii //weight: 1
        $x_1_3 = "explore we moon" ascii //weight: 1
        $x_1_4 = "$f647afa1-68f1-4859-af0d-09db821e0d3b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_AZJA_2147932019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.AZJA!MTB"
        threat_id = "2147932019"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 03 08 20 0b 02 00 00 58 20 0a 02 00 00 59 17 59 17 58 03 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_NFA_2147933367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.NFA!MTB"
        threat_id = "2147933367"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0c 17 58 93 11 05 61 13 06 17 13 0e 38 0c ff ff ff 11 0c 19 58 13 0c 11 06 1f 1f 5f}  //weight: 2, accuracy: High
        $x_1_2 = {11 0c 11 07 58 11 09 59 93 61 11 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_ZHT_2147937017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.ZHT!MTB"
        threat_id = "2147937017"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {01 0a 16 0b 38 13 00 00 00 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 3f e4 ff ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_SFG_2147938515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.SFG!MTB"
        threat_id = "2147938515"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 1d 00 00 0a 7e 02 00 00 04 6f 1e 00 00 0a 0a 7e 03 00 00 04 06 28 11 29 00 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_MMK_2147939449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.MMK!MTB"
        threat_id = "2147939449"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 00 00 00 00 fe 0e 01 00 fe 0c 01 00 20 01 00 00 00 40 00 00 00 00 73 1d 00 00 0a 7e 02 00 00 04 6f ?? 00 00 0a 0a 7e 03 00 00 04 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_SISI_2147940711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.SISI!MTB"
        threat_id = "2147940711"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 8d 24 00 00 01 13 04 7e ?? ?? ?? 04 02 1a 58 11 04 16 08 28 12 00 00 0a 28 56 00 00 0a 11 04 16}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_SLEO_2147941409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.SLEO!MTB"
        threat_id = "2147941409"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "DarkCrystal RAT" ascii //weight: 5
        $x_5_2 = "Something is fishy. [{0}]" ascii //weight: 5
        $x_1_3 = "[Screenshot] Saving screenshots from" ascii //weight: 1
        $x_1_4 = "[Clipboard] Saving information..." ascii //weight: 1
        $x_1_5 = "[SystemInfromation] Saving information..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_ZLU_2147942269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.ZLU!MTB"
        threat_id = "2147942269"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {17 58 20 00 01 00 00 5d 7d 13 00 00 04 02 02 7b 14 00 00 04 02 7b 12 00 00 04 02 7b 13 00 00 04 91 58 20 00 01 00 00 5d 7d 14 00 00 04 02 02 7b 13 00 00 04 02 7b 14 00 00 04 28 ?? 00 00 06 02 7b 12 00 00 04 02 7b 12 00 00 04 02 7b 13 00 00 04 91 02 7b 12 00 00 04 02 7b 14 00 00 04 91 58 20 00 01 00 00 5d 91 0c 06 07 03 07 91 08 61 d2 9c 07 17 58 0b 07 03 8e 69 3f 7b ff ff ff 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_PCO_2147945129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.PCO!MTB"
        threat_id = "2147945129"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 40 02 00 0a 6f 41 02 00 0a 00 09 08 1f 10 6f 40 02 00 0a 6f 42 02 00 0a 00 09 09 6f 43 02 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_SLUU_2147945865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.SLUU!MTB"
        threat_id = "2147945865"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1f 1a 28 1d 00 00 0a 00 28 1e 00 00 0a 72 01 00 00 70 28 1f 00 00 0a 6f 20 00 00 0a 0c 08 28 21 00 00 0a 0d 7e 07 00 00 04 2d 58}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_SLDG_2147948107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.SLDG!MTB"
        threat_id = "2147948107"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 4d 00 00 0a 72 54 01 00 70 6f 4e 00 00 0a 0a 06 6f 4f 00 00 0a d4 8d 2a 00 00 01 0b 06 07 16 07 8e 69 6f 50 00 00 0a 26 28 51 00 00 0a 0c 08 28 52 00 00 0a 1f ?? 28 53 00 00 0a 6f 54 00 00 0a 6f 55 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_LM_2147948206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.LM!MTB"
        threat_id = "2147948206"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {02 28 3f 00 00 0a 6f 40 00 00 0a 0a 14 0b 06 6f 41 00 00 0a 8e 69 16 31 10 17 8d 0b 00 00 01 25 16 16 8d 15 00 00 01 a2 0b 06 14 07 74 0a 00 00 1b 6f 42 00 00 0a 26}  //weight: 20, accuracy: High
        $x_10_2 = {73 38 00 00 0a 0b 00 07 02 6f 39 00 00 0a 0c 08 28 3a 00 00 0a 73 3b 00 00 0a 0a de 20 08 2c 06 08 6f 3c 00 00 0a dc 28 1e 00 00 0a 20 d0 07 00 00 28 3d 00 00 0a 28 3e 00 00 0a de c9 06 2a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_GTD_2147948321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.GTD!MTB"
        threat_id = "2147948321"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {04 06 08 16 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 08 17 d6 0c 08 07 31 de}  //weight: 10, accuracy: Low
        $x_1_2 = "L05xS0NEVHBnLnBuZw" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRat_MZV_2147951076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRat.MZV!MTB"
        threat_id = "2147951076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0a 38 bc 00 00 00 00 28 b4 08 00 0a 13 09 11 09 28 ?? 08 00 0a 72 27 07 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 28 ?? 08 00 0a 72 69 07 00 70 6f ?? 00 00 0a 6f ?? 08 00 0a 00 11 09 11 09 6f ?? 08 00 0a 11 09 6f ?? 08 00 0a 6f ?? 08 00 0a 13 0a 02 03 9a 28 ?? 00 00 0a 13 0b 11 0b 73 aa 08 00 0a 13 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

