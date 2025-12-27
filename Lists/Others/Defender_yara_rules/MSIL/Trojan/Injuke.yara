rule Trojan_MSIL_Injuke_MB_2147807600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.MB!MTB"
        threat_id = "2147807600"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7f3c1c2e-e1b6-4e24-b8fe-43ed675ecfdc" ascii //weight: 1
        $x_1_2 = "Hotspot Shield 7.9.0" ascii //weight: 1
        $x_1_3 = "Vtzqrskubtncovsrqdpsxbnt" ascii //weight: 1
        $x_1_4 = "RijndaelManaged" ascii //weight: 1
        $x_1_5 = "MemoryStream" ascii //weight: 1
        $x_1_6 = "CipherMode" ascii //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
        $x_1_8 = "CryptoStream" ascii //weight: 1
        $x_1_9 = "set_KeySize" ascii //weight: 1
        $x_1_10 = "CreateDecryptor" ascii //weight: 1
        $x_1_11 = "powershell" ascii //weight: 1
        $x_1_12 = "Test-Connection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_MC_2147809049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.MC!MTB"
        threat_id = "2147809049"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uRBqpKYtSt" wide //weight: 1
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = "Test-Connection facebook.com" wide //weight: 1
        $x_1_4 = "esaeler/ gifnocpi" wide //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
        $x_1_6 = "GetTypes" ascii //weight: 1
        $x_1_7 = "Invoke" ascii //weight: 1
        $x_1_8 = "DoFoo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_NZA_2147835626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.NZA!MTB"
        threat_id = "2147835626"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 08 06 8e 69 5d 91 7e ?? ?? ?? 04 08 91 61 d2 6f ?? ?? ?? 0a 08 17 58 0c 08 7e ?? ?? ?? 04 8e 69 32 dc}  //weight: 1, accuracy: Low
        $x_1_2 = {21 52 00 76 00 67 00 6e 00 77 00 61 00 6c 00 6e 00 64 00 74 00 79 00 70 00 65 00 63 00 69 00 61}  //weight: 1, accuracy: High
        $x_1_3 = "996b-1f0a067aa947" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ABB_2147835895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ABB!MTB"
        threat_id = "2147835895"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 8e 69 5d 91 02 11 02 91 61 d2 6f ?? ?? ?? 0a 38 00 00 00 00 11 02 17 58 13 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SVP_2147836549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SVP!MTB"
        threat_id = "2147836549"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 00 7e 07 00 00 04 11 02 7e 07 00 00 04 8e 69 5d 91 02 11 02 91 61 d2 6f ?? ?? ?? 0a 38 5a 00 00 00 11 02 02 8e 69 3f d4 ff ff ff 20 00 00 00 00 7e 41 00 00 04 7b 46 00 00 04 39 93 ff ff ff 26 20 00 00 00 00 38 88 ff ff ff 38 d2 ff ff ff 20 03 00 00 00 38 79 ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SPPV_2147836553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SPPV!MTB"
        threat_id = "2147836553"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 08 08 18 5d 2c 08 07 08 91 1f 09 61 2b 05 07 08 91 1b 61 d2 9c 08 17 58 0c 08 07 8e 69 32 e0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_RI_2147836566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.RI!MTB"
        threat_id = "2147836566"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 11 08 11 0a 11 0d d3 18 5a 58 49 d3 1a 5a 58}  //weight: 5, accuracy: High
        $x_1_2 = "$PASSWORD$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AHK_2147837060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AHK!MTB"
        threat_id = "2147837060"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 06 09 06 09 8e 69 5d 91 08 06 91 61 d2 9c 06 17 58 0a 15 2c 0a 06 08 8e 69 32 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ABER_2147837562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ABER!MTB"
        threat_id = "2147837562"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b 0a 2b 0b 18 2b 0b 1f 10 2b 0e 2a 03 2b f3 02 2b f2 6f ?? ?? ?? 0a 2b ee 28 ?? ?? ?? 0a 2b eb}  //weight: 3, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "GetResponseStream" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SPQP_2147837741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SPQP!MTB"
        threat_id = "2147837741"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 dc 00 00 70 19 2d 1f 26 28 ?? ?? ?? 0a 11 05 6f ?? ?? ?? 0a 0d 08 8e 69 8d 03 00 00 01 13 04 16 0a 2b 1b 0c 2b d9 13 05 2b de 11 04 06 09 06 09 8e 69 5d 91 08 06 91 61 d2 9c 06 17 58 0a 06 08 8e 69 32 e6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ANW_2147837824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ANW!MTB"
        threat_id = "2147837824"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 07 91 06 59 d2 9c 00 07 17 58 0b 07 7e ?? ?? ?? 04 8e 69 fe 04 0c 08 2d db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SRP_2147838220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SRP!MTB"
        threat_id = "2147838220"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {9a 2b 4b 06 09 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 17 58 16 2d fb 16 2d f8 0c 08 07 8e 69 32 dd 06 2a 73 1f 00 00 0a 38 a3 ff ff ff 28 ?? ?? ?? 06 38 a2 ff ff ff 6f ?? ?? ?? 0a 38 9d ff ff ff 0a}  //weight: 5, accuracy: Low
        $x_2_2 = "/147.182.192.85/common_Jjhlyxld.png" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SRQP_2147838941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SRQP!MTB"
        threat_id = "2147838941"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {9a 2b 4b 06 09 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 17 58 16 2d fb 16 2d f8 0c 08 07 8e 69 32 dd 06 2a 73 1f 00 00 0a 38 a3 ff ff ff 28 ?? ?? ?? 06 38 a2 ff ff ff 6f ?? ?? ?? 0a 38 9d ff ff ff 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AIN_2147839130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AIN!MTB"
        threat_id = "2147839130"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 1d 00 00 00 09 6f ?? ?? ?? 0a 13 07 08 11 07 07 02 11 07 18 5a 18 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_RD_2147839395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.RD!MTB"
        threat_id = "2147839395"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jxNYDwqiyIxoNSWoHelOuALanY" ascii //weight: 1
        $x_1_2 = "capdone.exe" ascii //weight: 1
        $x_1_3 = "EtRFkXFAAkjgfKmAtANODFtQogUX" wide //weight: 1
        $x_1_4 = "ywgpfou" wide //weight: 1
        $x_1_5 = "exmteek" wide //weight: 1
        $x_1_6 = "pclglqq" wide //weight: 1
        $x_1_7 = "fftvffb" wide //weight: 1
        $x_1_8 = "yivoifx" wide //weight: 1
        $x_1_9 = {e2 81 ab e2 80 8c e2 81 ac e2 80 8c e2 80 8c e2 81 ac e2 81 ac e2 81 af e2 80 ab e2 80 ad e2 80 aa e2 81 aa e2 81 aa e2 80 ab e2 80 8e e2 81 ac e2 80 8c e2 81 ab e2 80 ab e2 80 8b e2 80 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_NEAC_2147839973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.NEAC!MTB"
        threat_id = "2147839973"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://85.209.134.86" wide //weight: 5
        $x_4_2 = "/c ping google.com" wide //weight: 4
        $x_2_3 = "newversion" ascii //weight: 2
        $x_1_4 = "IDAT-R8" ascii //weight: 1
        $x_1_5 = "System.Windows.Forms" ascii //weight: 1
        $x_1_6 = "set_WindowStyle" ascii //weight: 1
        $x_1_7 = "ProcessStartInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_NIJ_2147840039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.NIJ!MTB"
        threat_id = "2147840039"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 1f 00 00 70 2b 03 2b 08 2a 28 ?? 00 00 06 2b f6 28 ?? 00 00 06 2b f1}  //weight: 5, accuracy: Low
        $x_1_2 = "Iylhqbhlvafsvf" wide //weight: 1
        $x_1_3 = "Computer Sentinel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AI_2147840098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AI!MTB"
        threat_id = "2147840098"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 73 00 00 04 06 7e 73 00 00 04 06 91 20 d6 02 00 00 59 d2 9c 00 06 17 58 0a 06 7e 73 00 00 04 8e 69 fe 04 0b 07 2d d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AI_2147840098_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AI!MTB"
        threat_id = "2147840098"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 24 00 00 04 00 de 0b 06 2c 07 06 6f 2c 00 00 0a 00 dc 16 0c 2b 1b 00 7e 24 00 00 04 08 7e 24 00 00 04 08 91 20 4b 03 00 00 59 d2 9c 00 08 17 58 0c 08 7e 24 00 00 04 8e 69 fe 04 0d 09 2d d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AI_2147840098_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AI!MTB"
        threat_id = "2147840098"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 09 16 04 a2 09 17 72 01 00 00 70 a2 09 18 28 ?? ?? ?? 0a a2 09 19 72 01 00 00 70 a2 09 1a 7e 11 00 00 04 a2 09 28 ?? ?? ?? 0a 0b 28 ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 0c 06 08 6f ?? ?? ?? 0a 26 06 18 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SPA_2147841202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SPA!MTB"
        threat_id = "2147841202"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_9_1 = {07 11 04 06 11 04 9a 1f 10 28 ?? ?? ?? 0a d2 9c 11 04 17 58 13 04 11 04 06 8e 69 fe 04 13 05 11 05 2d dd}  //weight: 9, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_NIA_2147841233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.NIA!MTB"
        threat_id = "2147841233"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 22 01 00 0a 6f ?? ?? 00 0a a2 25 18 73 ?? ?? 00 0a 06 1e 06 6f ?? ?? 00 0a 1e da 6f ?? ?? 00 0a 28 ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "3RGKh7p" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_DB_2147841540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.DB!MTB"
        threat_id = "2147841540"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 01 11 00 11 02 11 00 8e 69 5d 91 7e ?? 00 00 04 11 02 91 61 d2 6f ?? 00 00 0a 38 [0-4] 11 01 6f ?? 00 00 0a 2a 73 ?? 00 00 0a 13 01 38 [0-4] 16 13 02 38}  //weight: 3, accuracy: Low
        $x_1_2 = "Xeefhpjbsazapyiahaj" wide //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_MA_2147841615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.MA!MTB"
        threat_id = "2147841615"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 16 08 8e 69 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 16 6a 31 0d 08 2c 0a 07 6f ?? ?? ?? 0a 13 05 de 0a de 06}  //weight: 5, accuracy: Low
        $x_2_2 = {72 01 00 00 70 28 04 00 00 06 ?? 2d 03 26 2b 07 80 01 00 00 04 2b 00 2a}  //weight: 2, accuracy: Low
        $x_2_3 = "powershell" wide //weight: 2
        $x_1_4 = "WebRequest" ascii //weight: 1
        $x_1_5 = "ThreadStart" ascii //weight: 1
        $x_1_6 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_MA_2147841615_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.MA!MTB"
        threat_id = "2147841615"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 11 01 28 1f 00 00 06 13 02 38 d8 00 00 00 11 08 17 6f ?? ?? ?? 0a 38 a0 00 00 00 11 02 11 03 20 e8 03 00 00 73 ?? 00 00 0a 13 04 38 18 00 00 00 1e 8d 17 00 00 01 25 d0 16 00 00 04 28 ?? ?? ?? 0a 13 03 38 d3 ff ff ff 11 08 11 04 11 08 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 38 93 00 00 00 11 05 11 08 6f ?? ?? ?? 0a 17 73 ?? 00 00 0a 13 06 38 00 00 00 00 00 11 06 03 16 03 8e 69 6f ?? ?? ?? 0a 38 00 00 00 00 11 06 6f ?? ?? ?? 0a 38 00 00 00 00 dd 3b}  //weight: 1, accuracy: Low
        $x_1_2 = "MemoryStream" ascii //weight: 1
        $x_1_3 = "get_KeySize" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "set_Key" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "powershell" ascii //weight: 1
        $x_1_9 = "Test-Connection" ascii //weight: 1
        $x_1_10 = "Sleep" ascii //weight: 1
        $x_1_11 = "NewMock" ascii //weight: 1
        $x_1_12 = "CollectMock" ascii //weight: 1
        $x_1_13 = "set_CreateNoWindow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SRPV_2147842359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SRPV!MTB"
        threat_id = "2147842359"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PO#28135 -" ascii //weight: 1
        $x_1_2 = "185.216.71.120/Dmombia.jpeg" wide //weight: 1
        $x_1_3 = "Ormktorjdl.Tnnwigjfoudfczljqf" wide //weight: 1
        $x_1_4 = "Fabdqat" wide //weight: 1
        $x_1_5 = "$7fb63569-56c5-4285-93ce-a487912b3e98" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SPD_2147842968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SPD!MTB"
        threat_id = "2147842968"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 72 01 00 00 70 28 ?? ?? ?? 06 0a 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 02 07 28 ?? ?? ?? 06 0c dd 06 00 00 00}  //weight: 4, accuracy: Low
        $x_1_2 = "Xqsygd.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_MBCI_2147843139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.MBCI!MTB"
        threat_id = "2147843139"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 1f 10 2b 15 2b 1a 2b 1f 2b 20 2b 25 2b 26 2a 28 ?? 00 00 0a 2b d5 0a 2b d4}  //weight: 1, accuracy: Low
        $x_1_2 = {53 00 65 00 76 00 67 00 75 00 63 00 61 00 6b 00 75 00 7a 00 62 00 6e 00 72 00 7a 00 6a 00 78 00 67 00 6a 00 6c 00 2e 00 5a 00 67 00 6a 00 61 00 67 00 62 00 71 00 70 00 69 00 70 00 61 00 63 00 64}  //weight: 1, accuracy: High
        $x_1_3 = "Ebvoqhusv" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_NEAD_2147843320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.NEAD!MTB"
        threat_id = "2147843320"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 75 00 00 0a 6f 77 00 00 0a 00 06 18 6f 78 00 00 0a 00 06 18 6f 79 00 00 0a 00 06 6f 7a 00 00 0a 0b 07 02 16 02 8e 69 6f 7b 00 00 0a 0c 2b 00 08 2a}  //weight: 10, accuracy: High
        $x_2_2 = "$$$_I_n_v_o_k_e_$$$" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SPL_2147843564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SPL!MTB"
        threat_id = "2147843564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 0f 00 00 0a 0a 28 10 00 00 0a 72 01 00 00 70 02 73 11 00 00 0a 28 12 00 00 0a 28 13 00 00 0a 28 14 00 00 0a 06 02 6f 15 00 00 0a 0b 25 07 28 16 00 00 0a 28 17 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = "onegbcloud.cfd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_EAU_2147843656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.EAU!MTB"
        threat_id = "2147843656"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 0a 28 02 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 02 07 28 ?? 00 00 06 0c dd ?? 00 00 00 26 dd ?? ff ff ff 08 2a}  //weight: 3, accuracy: Low
        $x_2_2 = "WindowsFormsApp47.Properties.Resources" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ABPD_2147843710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ABPD!MTB"
        threat_id = "2147843710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 0c 07 08 17 73 ?? ?? ?? 0a 0d 00 09 02 28 ?? ?? ?? 06 00 09 28 ?? ?? ?? 06 00 07 28 ?? ?? ?? 06 13 04 de 2c 09 2c 07 09 6f ?? ?? ?? 0a 00 dc 3c 00 06 28 ?? ?? ?? 06 00 06 28}  //weight: 4, accuracy: Low
        $x_1_2 = "FlushFinalBlock" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_EAM_2147843763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.EAM!MTB"
        threat_id = "2147843763"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {1a 2d 24 26 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 1c 2d 13 26 07 16 07 8e 69 15 2d 0d 26 26 26 07 0c de 10 0a 2b da 0b 2b eb 28 ?? 00 00 0a 2b ef 26 de be}  //weight: 3, accuracy: Low
        $x_2_2 = "comicmaster.org.uk/img/css/design/fabric/bo/Seqqgdsrh.bmp" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AP_2147843854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AP!MTB"
        threat_id = "2147843854"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 18 5b 02 08 18 6f 14 00 00 0a 1f 10 28 15 00 00 0a 9c 08 18 58 0c 08 06 32}  //weight: 2, accuracy: High
        $x_2_2 = {cd ef b9 ef ca ef bf ef b8 ef be ef bd ef c9 ef cc ef b8 ef be ef cf ef c9 ef cc ef ce ef be ef c5 ef b9 ef cb ef c5 ef c8 ef ce ef c5 ef c9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AJK_2147843944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AJK!MTB"
        threat_id = "2147843944"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0b 2b 1b 00 7e 01 00 00 04 07 7e 01 00 00 04 07 91 20 56 02 00 00 59 d2 9c 00 07 17 58 0b 07 7e 01 00 00 04 8e 69 fe 04 0c 08 2d d7}  //weight: 2, accuracy: High
        $x_1_2 = "JOKAFWAIUFH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_EAN_2147844120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.EAN!MTB"
        threat_id = "2147844120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {1a 2d 24 26 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 1c 2d 13 26 07 16 07 8e 69 1d 2d 0d 26 26 26 07 0c de 10 0a 2b da 0b 2b eb 28 ?? 00 00 0a 2b ef 26 de be}  //weight: 3, accuracy: Low
        $x_2_2 = "paweer.ru/panel/uploads/Bwufxyjt.bmp" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_FAR_2147845752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.FAR!MTB"
        threat_id = "2147845752"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 02 2a 00 38 00 00 00 00 00 72 ?? 00 00 70 28 ?? 00 00 06 13 00 38 ?? 00 00 00 fe 0c 01 00 45 ?? 00 00 00 3c 00 00 00 38 ?? 00 00 00 28 ?? 00 00 0a 11 00 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 13 02 20 00 00 00 00 7e ?? 08 00 04 7b ?? 09 00 04 3a ?? ff ff ff 26 ?? 00 00 00 00 38 ?? ff ff ff dd}  //weight: 3, accuracy: Low
        $x_2_2 = "192.3.215.60/uo7/Fbnkrtltw.bmp" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ABSU_2147845761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ABSU!MTB"
        threat_id = "2147845761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String" ascii //weight: 1
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_3_3 = {38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 33 00 37}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_FAS_2147845780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.FAS!MTB"
        threat_id = "2147845780"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {61 d1 9d fe ?? 01 00 20 1e 5b 86 0a 65 20 13 dc f0 11 61 66 20 0f 87 76 1b 61 59 25 fe ?? 01 00 20 57 d0 24 27 20 a8 2f db d8 58 66 65 3c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ABQU_2147845861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ABQU!MTB"
        threat_id = "2147845861"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 23 00 00 70 28 ?? ?? ?? 06 13 00 38 ?? ?? ?? 00 28 ?? ?? ?? 06 11 00 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 13 01 38 ?? ?? ?? 00 dd ?? ?? ?? ff 26 38 ?? ?? ?? 00 dd 05}  //weight: 4, accuracy: Low
        $x_3_2 = "179.43.175.187/ksjy/Fnavenf.dat" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_FAT_2147845928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.FAT!MTB"
        threat_id = "2147845928"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 07 18 5b 8d ?? 00 00 01 0c 16 0d 38 ?? 00 00 00 08 09 18 5b 06 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 09 18 58 0d 09 07 32 e4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_PSKX_2147846126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.PSKX!MTB"
        threat_id = "2147846126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 2b 00 00 70 28 09 00 00 06 13 00 38 00 00 00 00 28 ?? ?? ?? 0a 11 00 6f ?? ?? ?? 0a 72 75 00 00 70 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 01 38 00 00 00 00 dd 10 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_PSLW_2147846179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.PSLW!MTB"
        threat_id = "2147846179"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 0b 00 00 06 0a 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 0c 00 00 06 75 0f 00 00 1b 73 ?? ?? ?? 0a 0b 28 04 00 00 2b 6f ?? ?? ?? 0a 0c 38 0e 00 00 00 08 6f ?? ?? ?? 0a 0d 07 09 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 2d ea}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ABRZ_2147846496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ABRZ!MTB"
        threat_id = "2147846496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Somebo4y.9ine.resources" ascii //weight: 3
        $x_3_2 = {53 00 6f 00 6d 00 65 00 62 00 6f 00 34 00 79 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73}  //weight: 3, accuracy: High
        $x_1_3 = "LagrangePolynomial" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ABVL_2147846879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ABVL!MTB"
        threat_id = "2147846879"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 11 2b 16 74 ?? 00 00 01 2b 16 74 ?? 00 00 1b 2b 16 2a 28 ?? ?? 00 06 2b e8 28 ?? ?? 00 06 2b e3 28 ?? ?? 00 06 2b e3 28 ?? ?? 00 06 2b e3}  //weight: 2, accuracy: Low
        $x_2_2 = {2b 05 2b 06 2b 0b 2a 02 2b f8 28 ?? 00 00 2b 2b f3 28 ?? 00 00 2b 2b ee}  //weight: 2, accuracy: Low
        $x_1_3 = "ReadAsByteArrayAsync" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_PSOU_2147847859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.PSOU!MTB"
        threat_id = "2147847859"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {14 0a 38 13 00 00 00 00 02 28 04 00 00 06 0a dd 06 00 00 00 26 dd 00 00 00 00 06 2c ea}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_PSPK_2147848360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.PSPK!MTB"
        threat_id = "2147848360"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7d 28 02 00 04 7e 0e 00 00 04 28 ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 12 02 e0 0f 01 e0 12 03 e0 6f ?? ?? ?? 06 13 04 11 04 16 fe 03 13 05 11 05 2c 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ABYT_2147848677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ABYT!MTB"
        threat_id = "2147848677"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2b 11 2b 16 74 ?? 00 00 01 2b 16 74 ?? 00 00 1b 2b 16 2a 28 ?? 00 00 06 2b e8 28 ?? 00 00 06 2b e3 28 ?? 00 00 06 2b e3 28 ?? 00 00 06 2b e3}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AADI_2147849825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AADI!MTB"
        threat_id = "2147849825"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 49 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 15 2d 09 26 12 00 18 2d 06 26 de 0d 0a 2b f5 28 ?? 00 00 06 2b f4 26 de 00 06 2c cf}  //weight: 2, accuracy: Low
        $x_1_2 = "ReadAsByteArrayAsync" ascii //weight: 1
        $x_1_3 = "delobiznesa.online/panel/uploads/Pocpzkohrjl.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_MBGO_2147850566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.MBGO!MTB"
        threat_id = "2147850566"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 11 05 11 20 9a 1f 10 28 ?? 00 00 0a b4 6f ?? 00 00 0a 00 11 20 17 d6 13 20 11 20 11 1f 31 df}  //weight: 1, accuracy: Low
        $x_1_2 = {51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 00 11 47 00 69 00 61 00 79 00 2e 00 43 00 43 00 4d}  //weight: 1, accuracy: High
        $x_1_3 = "217e08a3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_NNJ_2147850783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.NNJ!MTB"
        threat_id = "2147850783"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 27 00 00 0a 13 04 11 04 11 04 6f ?? ?? 00 0a 6f ?? ?? 00 0a 13 05 72 ?? ?? 00 70 28 ?? ?? 00 0a 08 28 ?? ?? 00 0a 13 06 11 06 28 ?? ?? 00 0a 26 11 06 09 72 ?? ?? 00 70 28 ?? ?? 00 0a 13 07 11 07 28 ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Dwfsgxetfnz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ASCI_2147851696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ASCI!MTB"
        threat_id = "2147851696"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 06 07 08 11 06 28 ?? 00 00 0a 09 06 6f ?? 00 00 0a 61 d2 9c 08 17 58 0c 06 17 58 0a 06 09 6f ?? 00 00 0a 33 02 16 0a 11 05 6f ?? 00 00 0a 2d c8}  //weight: 4, accuracy: Low
        $x_1_2 = {32 00 34 00 31 00 33 00 38 00 30 00 33 00 33 00 32 00 31 00 37 00 31 00 38 00 37 00 30 00 32 00 34 00 31 00 36 00 37 00 32 00 30 00 31 00 32 00 35 00 30 00 31 00 34 00 38 00 31 00 38 00 31 00 30 00 34 00 38 00 31 00 30 00 33 00 31 00 33 00 38 00 31 00 35 00 34 00 32 00 35 00 34 00 32 00 30 00 35 00 32 00 31 00 32 00 32 00 35 00 32 00 30 00 36 00 31 00 32}  //weight: 1, accuracy: High
        $x_1_3 = {31 00 35 00 34 00 30 00 30 00 33 00 31 00 31 00 38 00 30 00 34 00 38 00 32 00 30 00 33 00 32 00 32 00 36 00 32 00 31 00 38 00 30 00 36 00 38 00 30 00 33 00 38 00 31}  //weight: 1, accuracy: High
        $x_1_4 = "512241141031000671210782012270" wide //weight: 1
        $x_1_5 = "18807821812614806202324911803" wide //weight: 1
        $x_1_6 = "21714007507310210819205620622714" wide //weight: 1
        $x_1_7 = "96241185180001042071133162164139" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Injuke_AMS_2147851792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AMS!MTB"
        threat_id = "2147851792"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 11 05 11 1f 9a 1f 10 28 ?? 00 00 0a 86 6f ?? 00 00 0a 00 11 1f 17 d6 13 1f 11 1f 11 1e 31 df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_PSTL_2147851864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.PSTL!MTB"
        threat_id = "2147851864"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 72 73 00 00 70 28 ?? 00 00 06 00 07 72 df 00 00 70 28 ?? 00 00 0a 0c 07 0d 73 18 00 00 0a 13 06 00 11 06 72 f1 00 00 70 08 6f ?? 00 00 0a 00 00 de 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ASCL_2147851966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ASCL!MTB"
        threat_id = "2147851966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 06 11 05 8e 69 17 da 13 1e 16 13 1f 2b 1d 11 06 11 1f 11 05 11 1f 9a 1f 10 28 ?? 00 00 0a 86 6f ?? 00 00 0a 00 11 1f 17 d6 13 1f 11 1f 11 1e 31 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ASCS_2147852634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ASCS!MTB"
        threat_id = "2147852634"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 8e 69 17 da 13 0f 16 13 10 2b 1b 11 07 11 06 11 10 9a 1f 10 28 ?? 00 00 0a b4 6f ?? 00 00 0a 00 11 10 17 d6 13 10 11 10 11 0f 31 df}  //weight: 1, accuracy: Low
        $x_1_2 = "DKJAYHGDKIUH KHJGDAGDJKAH" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AALU_2147888325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AALU!MTB"
        threat_id = "2147888325"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0a 06 18 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 72 01 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 02 06 6f ?? 00 00 0a 7d ?? 00 00 04 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "kYMdGCDcfbQyC5F1SO7NYrXfD6qvi39tRT2XiDb2nY8=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AMAB_2147888631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AMAB!MTB"
        threat_id = "2147888631"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 07 11 04 11 01 11 04 91 11 00 11 04 11 00 28 ?? 00 00 06 5d 6f ?? 00 00 0a 61 d2 9c}  //weight: 1, accuracy: Low
        $x_1_2 = "HttpClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ASDP_2147889289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ASDP!MTB"
        threat_id = "2147889289"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 07 11 10 17 8d ?? 00 00 01 25 16 11 06 11 10 9a 1f 10 28 ?? 00 00 0a 86 9c 6f ?? 00 00 0a 00 11 10 17 d6 13 10 11 10 11 0f 31 d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AAOA_2147889503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AAOA!MTB"
        threat_id = "2147889503"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {08 11 08 17 8d ?? 00 00 01 25 16 07 11 08 9a 1f 10 28 ?? 00 00 0a 9c}  //weight: 3, accuracy: Low
        $x_1_2 = "DeleteMC" wide //weight: 1
        $x_1_3 = "Lo-ad" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AMAA_2147890140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AMAA!MTB"
        threat_id = "2147890140"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 11 0f 17 8d ?? 00 00 01 25 16 11 05 11 0f 9a 1f 10 28 ?? 01 00 0a 86 9c 6f ?? 01 00 0a 00 11 0f 17 d6 13 0f 11 0f 11 0e 31 d4}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 00 6f 00 2d 00 61 00 64 00 20 00 01 03 2d 00 01 11 44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43}  //weight: 1, accuracy: High
        $x_1_3 = "Split" ascii //weight: 1
        $x_1_4 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AMAC_2147890142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AMAC!MTB"
        threat_id = "2147890142"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 06 11 0f 17 8d ?? ?? 00 01 25 16 11 05 11 0f 9a 1f 10 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 11 0f 17 d6 13 0f 11 0f 11 0e 31 d5}  //weight: 5, accuracy: Low
        $x_5_2 = {4c 00 6f 00 2d 00 61 00 64 00 20 00 01 03 2d 00 01 11 44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AAOR_2147890294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AAOR!MTB"
        threat_id = "2147890294"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 11 04 06 11 04 91 20 5d 06 00 00 59 d2 9c 00 11 04 17 58 13 04 11 04 06 8e 69 fe 04 13 05 11 05 3a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AAPK_2147891403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AAPK!MTB"
        threat_id = "2147891403"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 72 df 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 73 ?? 00 00 0a 72 03 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 73 ?? 00 00 0a 72 19 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 73 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 0b de 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_KAC_2147891726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.KAC!MTB"
        threat_id = "2147891726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 01 11 02 11 00 11 02 91 20 ?? ?? ?? ?? ?? ?? 00 00 06 28 ?? 00 00 06 59 d2 9c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SSPP_2147891823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SSPP!MTB"
        threat_id = "2147891823"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 06 6f ?? 02 00 0a 06 6f ?? 02 00 0a 6f ?? 02 00 0a 13 04 73 ?? 02 00 0a 0b 02 73 ?? 02 00 0a 0c 08 11 04 16 73 ?? 02 00 0a 0d 09 07 6f ?? 02 00 0a 07 6f ?? 02 00 0a 13 05 de 1f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AAQW_2147892090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AAQW!MTB"
        threat_id = "2147892090"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 00 16 73 ?? 00 00 0a 13 09 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 ?? ff ff ff 26 20 00 00 00 00 38 ?? ff ff ff 11 01 16 28 ?? 00 00 0a 13 02}  //weight: 3, accuracy: Low
        $x_1_2 = {11 0b 28 01 00 00 2b 28 02 00 00 2b 28 16 00 00 0a 13 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_KAD_2147892849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.KAD!MTB"
        threat_id = "2147892849"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TBDtSTaelmToFrae.dll" ascii //weight: 1
        $x_1_2 = "QZtcZTrNjjgt.dll" ascii //weight: 1
        $x_1_3 = "wprWzpFIcDFH.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_KAD_2147892849_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.KAD!MTB"
        threat_id = "2147892849"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "95.214.24.37" wide //weight: 1
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_MBJV_2147892889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.MBJV!MTB"
        threat_id = "2147892889"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {da 04 d6 1f 1a 5d 13 07 11 0b}  //weight: 1, accuracy: High
        $x_1_2 = {7d 00 00 03 7d 00 00 03 30 00 00 0f 20 00 4c 00 6f 00 2d 00 61 00 64 00 20 00 00 03 2d 00 00 11 44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SK_2147892976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SK!MTB"
        threat_id = "2147892976"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 05 11 0d 58 13 05 00 11 0d 17 58 13 0d 11 0d 1f 0a fe 04 13 0e 11 0e 2d e5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SK_2147892976_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SK!MTB"
        threat_id = "2147892976"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Eikcr.exe" ascii //weight: 1
        $x_1_2 = "Eikcr.Factories" ascii //weight: 1
        $x_1_3 = "Baqetiwfdpe.Properties" ascii //weight: 1
        $x_1_4 = "{78097044-8808-460d-9f2d-dd7c9a50d292}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AAST_2147893073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AAST!MTB"
        threat_id = "2147893073"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 13 17 2b 16 00 11 11 11 17 11 11 11 17 91 1f 20 61 d2 9c 00 11 17 17 58 13 17 11 17 11 11 8e 69 fe 04 13 18 11 18 2d dc}  //weight: 2, accuracy: High
        $x_2_2 = {11 11 11 19 11 11 11 19 91 1f 16 61 d2 9c 00 11 19 17 58 13 19 11 19 11 11 8e 69 fe 04 13 1a 11 1a 2d dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AASV_2147893087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AASV!MTB"
        threat_id = "2147893087"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 00 72 45 00 00 70 28 ?? 00 00 06 72 77 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 13 01}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AATK_2147893494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AATK!MTB"
        threat_id = "2147893494"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 05 2b 23 09 11 05 16 6f ?? 00 00 0a 13 06 12 06 28 ?? 00 00 0a 13 07 11 04 11 07 6f ?? 00 00 0a 11 05 17 58 13 05 11 05 09 6f ?? 00 00 0a 32 d3 11 04 6f ?? 00 00 0a 13 08 de 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AATX_2147893845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AATX!MTB"
        threat_id = "2147893845"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0c 2b 12 00 07 08 06 08 91 02 28 ?? 00 00 06 9c 00 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d e4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AATA_2147893851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AATA!MTB"
        threat_id = "2147893851"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0d 2b 3a 08 13 04 16 13 05 11 04 12 05 28 ?? 00 00 0a 07 09 18 6f ?? 00 00 0a 06 28 ?? 00 00 0a 13 06 08 09 11 06 6f ?? 00 00 0a de 0c 11 05 2c 07 11 04 28 ?? 00 00 0a dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AMSA_2147894273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AMSA!MTB"
        threat_id = "2147894273"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 16 0d 38 ?? 00 00 00 07 09 16 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 13 05 08 11 05 6f ?? 00 00 0a 09 17 58 0d 09 07 6f ?? 00 00 0a 32 d8 08 6f ?? 00 00 0a 13 06 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AMAD_2147894627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AMAD!MTB"
        threat_id = "2147894627"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 00 11 01 11 00 11 01 93 20 ?? 00 00 00 61 02 61 d1 9d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_GND_2147894725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.GND!MTB"
        threat_id = "2147894725"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 07 16 6f ?? ?? ?? 0a 13 08 12 08 28 ?? ?? ?? 0a 13 06 11 05 7b ?? ?? ?? ?? 11 06 6f ?? ?? ?? 0a 07 17 58 0b 07 11 04 6f ?? ?? ?? 0a 32 d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_GNE_2147894726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.GNE!MTB"
        threat_id = "2147894726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "m_b595edd43d3540e58b85f7088e052645" ascii //weight: 1
        $x_1_2 = "f8DBD67B7495DF03" ascii //weight: 1
        $x_1_3 = "Gopjreg" ascii //weight: 1
        $x_1_4 = "Ghvihovn.Gpilcxrw" ascii //weight: 1
        $x_1_5 = "Doebcax" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_GNF_2147894734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.GNF!MTB"
        threat_id = "2147894734"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 05 07 16 6f ?? ?? ?? 0a 13 0a 12 0a 28 ?? ?? ?? 0a 13 08 11 06 11 08 6f ?? ?? ?? 0a 07 17 58 0b 07 11 05 6f ?? ?? ?? 0a 32 d5}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AAWA_2147895756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AAWA!MTB"
        threat_id = "2147895756"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 00 11 00 28 ?? 06 00 06 11 00 28 ?? 06 00 06 28 ?? 06 00 06 13 04 20 02 00 00 00 38 ?? ff ff ff 11 00 20 4a dd b5 e4 28 ?? 06 00 06 28 ?? 06 00 06 6f ?? 04 00 0a 20 03 00 00 00 38 ?? ff ff ff 73 ?? 04 00 0a 13 0a 20 00 00 00 00 7e ?? 03 00 04 7b ?? 03 00 04 3a ?? ff ff ff 26}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ABOR_2147896336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ABOR!MTB"
        threat_id = "2147896336"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {0a 0c 08 07 17 73 ?? ?? ?? 0a 0d 00 09 03 16 03 8e 69 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 13 04 de 21 09 2c 07 09 6f ?? ?? ?? 0a 00 dc 3f 00 06 6f ?? ?? ?? 0a 0b 73}  //weight: 6, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "FlushFinalBlock" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ABPZ_2147896713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ABPZ!MTB"
        threat_id = "2147896713"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {09 11 05 9a 13 09 11 04 11 09 1f 10 28 ?? ?? ?? 0a b4 6f ?? ?? ?? 0a 00 11 05 17 d6 13 05 00 11 05 09 8e 69 fe 04 13 0a 11 0a 2d d4}  //weight: 4, accuracy: Low
        $x_1_2 = "Pirates.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AAFG_2147896758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AAFG!MTB"
        threat_id = "2147896758"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 06 6f ?? 02 00 0a 06 6f ?? 02 00 0a 6f ?? 02 00 0a 13 04 73 ?? 02 00 0a 0b 02 73 ?? 02 00 0a 0c 08 11 04 16 73 ?? 02 00 0a 0d 09 07 6f ?? 02 00 0a 07 6f ?? 02 00 0a 13 05 de 1f 09 6f ?? 00 00 0a dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AAQJ_2147896763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AAQJ!MTB"
        threat_id = "2147896763"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Tmxuywtiapd.Properties.Resources.resources" ascii //weight: 2
        $x_1_2 = "cd1c9355-81e6-4436-950c-6e635735ab85" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AAWV_2147896907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AAWV!MTB"
        threat_id = "2147896907"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 08 02 8e 69 5d 1c 58 1c 59 1d 58 1d 59 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 1c 58 1c 59 1d 58 1d 59 91 61 28 ?? 00 00 0a 02 08 20 87 10 00 00 58 20 86 10 00 00 59 02 8e 69 5d 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 31 9f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AAWM_2147896943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AAWM!MTB"
        threat_id = "2147896943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 08 2b 34 00 11 04 72 f5 00 00 70 12 08 28 ?? 00 00 0a 28 ?? 00 00 0a 11 05 1f 5a 20 97 00 00 00 6f ?? 00 00 0a 73 ?? 00 00 06 6f ?? 00 00 0a 00 00 11 08 17 58 13 08 11 08 1f 0a fe 04 13 09 11 09 2d c0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AAWY_2147897011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AAWY!MTB"
        threat_id = "2147897011"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 0b 06 07 16 7e ?? 00 00 04 6f ?? 00 00 0a 26 07 16 28 ?? 00 00 0a 0c 06 16 73 ?? 00 00 0a 0d 08 8d ?? 00 00 01 13 04 09 11 04 16 08 6f ?? 00 00 0a 26 11 04 28 ?? 00 00 2b 28 ?? 00 00 2b 13 05 de 14}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AAXN_2147897513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AAXN!MTB"
        threat_id = "2147897513"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 09 20 33 2c 00 00 28 ?? 04 00 06 28 ?? 00 00 0a 20 29 2d 00 00 28 ?? 04 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 13 02}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_PSBF_2147899323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.PSBF!MTB"
        threat_id = "2147899323"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 62 00 00 0a 00 72 53 46 00 70 28 6e ?? ?? ?? 28 28 ?? ?? ?? 5b 58 00 23 00 00 00 00 50 48 f5 40 23 00 00 00 00 60 60 dc 40 28 67 ?? ?? ?? 59 28 62 ?? ?? ?? 00 72 c5 46 00 70 28 6e ?? ?? ?? 28 28 ?? ?? ?? 5b 58 5a 8d 5f 00 00 01 0a 7e 29 ?? ?? ?? 28 ba ?? ?? ?? 0b 7e 2a ?? ?? ?? 07 06 28 e5 ?? ?? ?? de 0f 07 2c 0b 7e 2b ?? ?? ?? 07 28 d2 ?? ?? ?? dc 06 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "CipherMode" ascii //weight: 1
        $x_1_3 = "RijndaelManaged" ascii //weight: 1
        $x_1_4 = "CryptoStreamMode" ascii //weight: 1
        $x_1_5 = "GetHashCode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ARA_2147899456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ARA!MTB"
        threat_id = "2147899456"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 11 05 09 11 05 09 8e 69 5d 91 07 11 05 91 61 d2 9c 11 05 17 58 13 05 11 05 07 8e 69 32 e0}  //weight: 2, accuracy: High
        $x_1_2 = "HttpWebRequest" ascii //weight: 1
        $x_1_3 = "WebResponse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SG_2147899853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SG!MTB"
        threat_id = "2147899853"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetDomain" ascii //weight: 1
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_2_3 = "simpleCAlculatorException_.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SG_2147899853_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SG!MTB"
        threat_id = "2147899853"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 8b 00 00 70 28 1b 00 00 0a 72 95 00 00 70 28 1c 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_KAE_2147900312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.KAE!MTB"
        threat_id = "2147900312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e1}  //weight: 5, accuracy: High
        $x_5_2 = {00 11 04 11 05 58 08 11 05 58 47 52 00 11 05 17 58 13 05 11 05 05 fe 04 13 06 11 06 2d e2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AMAF_2147900821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AMAF!MTB"
        threat_id = "2147900821"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 11 04 73 ?? 00 00 0a 09 07 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 06 28 ?? 00 00 2b 16 fe 01 13}  //weight: 1, accuracy: Low
        $x_1_2 = {02 1f 10 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_PTGQ_2147901034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.PTGQ!MTB"
        threat_id = "2147901034"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b f6 09 28 ?? 00 00 0a 28 ?? 01 00 06 74 0a 00 00 1b 0a 06 75 0a 00 00 1b 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_CCHE_2147901772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.CCHE!MTB"
        threat_id = "2147901772"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 11 04 28 ?? 03 00 06 00 25 17 28 ?? 03 00 06 00 25 18 28 ?? 03 00 06 00 25 07 28 ?? 03 00 06 00 13 08 20 ?? 00 00 00 38 ?? fe ff ff 08 11 04 73 ?? ?? ?? ?? 09 07 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SPXX_2147902592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SPXX!MTB"
        threat_id = "2147902592"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 08 08 28 ?? ?? ?? 0a 9c 07 08 03 08 03 8e 69 5d 91 9c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SPDP_2147904142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SPDP!MTB"
        threat_id = "2147904142"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {38 37 00 00 00 11 03 11 01 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 16 11 01 8e 69}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_GZAA_2147904585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.GZAA!MTB"
        threat_id = "2147904585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 09 08 6f ?? 00 00 0a 09 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05}  //weight: 2, accuracy: Low
        $x_2_2 = {11 08 02 74 ?? 00 00 1b 16 02 14}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_IZAA_2147905993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.IZAA!MTB"
        threat_id = "2147905993"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 09 07 09 91 20 ab 6f 00 00 28 ?? 08 00 06 28 ?? 00 00 0a 59 d2 9c 09 17 58 0d 09 07 8e 69 32 df}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_JBAA_2147906057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.JBAA!MTB"
        threat_id = "2147906057"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 09 07 09 91 18 28 ?? 09 00 06 28 ?? 08 00 06 28 ?? 09 00 06 59 d2 9c 09 19 28 ?? 09 00 06 58 0d 09 07 8e 69 32 d9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_JCAA_2147906064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.JCAA!MTB"
        threat_id = "2147906064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 06 11 03 16 11 03 8e 69 6f ?? 00 00 0a 13 07}  //weight: 2, accuracy: Low
        $x_1_2 = "dskfoiwehf" wide //weight: 1
        $x_1_3 = "wewfhhidsfwe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_JGAA_2147906218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.JGAA!MTB"
        threat_id = "2147906218"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 09 07 09 91 20 ?? ?? 00 00 28 ?? 08 00 06 28 ?? 00 00 0a 59 d2 9c 09 17 58 0d 09 07 8e 69 32 df}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_JLAA_2147906355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.JLAA!MTB"
        threat_id = "2147906355"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0d 06 07 09 9c 1d 2c 22 07 16 2d cc 17 25 2c 0e 58 0b 07 02 7b ?? 00 00 04 6f ?? 00 00 0a 16 2d ec 32 bc 02 06 7d ?? 00 00 04 02 7b ?? 00 00 04 25 2d 03 26 2b 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_JXAA_2147906790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.JXAA!MTB"
        threat_id = "2147906790"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 06 11 0a 16 11 0a 8e 69 28 ?? 00 00 06 13 07}  //weight: 2, accuracy: Low
        $x_1_2 = "dskfoiwehf" wide //weight: 1
        $x_1_3 = "wewfhhidsfwe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_MBYD_2147908216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.MBYD!MTB"
        threat_id = "2147908216"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4D5A9~3~|04~|FFFF~B8~~~|4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_LEAA_2147908347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.LEAA!MTB"
        threat_id = "2147908347"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 2b 42 2b 25 2b 41 7b ?? 00 00 04 7b ?? 00 00 04 07 08 16 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 08 17 58 0c 08 07 6f ?? 00 00 0a 32 d2}  //weight: 4, accuracy: Low
        $x_1_2 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_LNAA_2147908639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.LNAA!MTB"
        threat_id = "2147908639"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {04 07 08 16 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 16 2d 13 08 16 2d 07 17 25 2c 09 58 0c 08 07 6f ?? 00 00 0a 32 c9}  //weight: 4, accuracy: Low
        $x_1_2 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AMAE_2147910626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AMAE!MTB"
        threat_id = "2147910626"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 17 58 11 ?? 5d 13 ?? 02 08 07 91 11 ?? 61 08 11 ?? 91 59 28 ?? ?? ?? ?? 13 ?? 08 07 11 ?? 28 ?? ?? ?? ?? d2 9c 07 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_NFAA_2147910934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.NFAA!MTB"
        threat_id = "2147910934"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 06 03 06 58 47 04 06 04 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 06 17 58 0a 06 02 8e 69 32 df}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_NNAA_2147911365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.NNAA!MTB"
        threat_id = "2147911365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 0c 11 02 6f ?? 00 00 0a 20 00 00 00 00 28 ?? 00 00 06 3a ?? ff ff ff 26 38 ?? ff ff ff 00 00 11 0c 28 ?? 00 00 06 13 09}  //weight: 2, accuracy: Low
        $x_2_2 = {11 09 11 03 16 11 03 8e 69 6f ?? 00 00 0a 13 07 38 00 00 00 00 11 07 13 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_NUAA_2147911613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.NUAA!MTB"
        threat_id = "2147911613"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {16 13 0e 2b 14 00 11 0d 11 0e 06 11 0b 11 0e 58 91 9c 00 11 0e 17 58 13 0e 11 0e 11 0c fe 04 13 0f 11 0f 2d e0}  //weight: 4, accuracy: High
        $x_1_2 = "CreateDecryptor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_MBYN_2147912390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.MBYN!MTB"
        threat_id = "2147912390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 04 09 11 04 16 11 04 8e 69 6f 0a}  //weight: 1, accuracy: High
        $x_5_2 = {59 6c 69 73 6d 6a 7a 61 67 77 00 48 65 6c 70 65}  //weight: 5, accuracy: High
        $x_5_3 = "SLL1CyFT97FO0MIitNnxlQ" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_OQAA_2147912391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.OQAA!MTB"
        threat_id = "2147912391"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 09 02 11 09 91 66 d2 9c 02 11 09 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 72 59 d2 81 ?? 00 00 01 02 11 09 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 33 58 d2 81 ?? 00 00 01 00 11 09 17 58 13 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SPLF_2147913475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SPLF!MTB"
        threat_id = "2147913475"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {d1 13 16 11 19 11 09 91 13 28 11 19 11 09 11 20 11 28 61 11 18 19 58 61 11 32 61 d2 9c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_MBYW_2147913733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.MBYW!MTB"
        threat_id = "2147913733"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 00 6f 00 61 00 64 00 00 27 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2f 00 6b 00 69 00 73 00 6f 00 6e 00 69 00 39 00 63 00 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_PKAA_2147913758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.PKAA!MTB"
        threat_id = "2147913758"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 0b 07 72 b9 00 00 70 18 18 8d ?? 00 00 01 25 16 7e ?? 00 00 04 a2 25 17 7e 14 00 00 04 a2 28 ?? 00 00 0a 74 ?? 00 00 01 0d 00 09 02 16 02 8e 69 6f ?? 00 00 0a 13 04 de 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_POAA_2147913868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.POAA!MTB"
        threat_id = "2147913868"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 72 f1 00 00 70 18 18 8d 10 00 00 01 25 16 7e ?? 00 00 04 a2 25 17 7e ?? 00 00 04 a2 28 ?? 00 00 0a 74 ?? 00 00 01 0a 06 02 16 02 8e 69 6f ?? 00 00 0a 0b de 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_PRAA_2147913959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.PRAA!MTB"
        threat_id = "2147913959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 09 18 6f ?? ?? 00 0a 1f 10 28 ?? ?? 00 0a 13 04 11 04 16 3f 08 00 00 00 08 11 04 6f ?? 00 00 0a 09 18 58 0d 09 07 6f ?? 00 00 0a 3f ?? ff ff ff 08 13 05 dd ?? 00 00 00 26 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AMAI_2147914042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AMAI!MTB"
        threat_id = "2147914042"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 09 16 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 13 05 06 11 05 6f ?? 00 00 0a 09 17 58 0d 09 08 6f ?? 00 00 0a 32 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_NJ_2147914183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.NJ!MTB"
        threat_id = "2147914183"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 16 1a 28 ?? 00 00 0a 11 07 20 ?? 36 0c d0 5a 20 ?? ea 13 a0 61 38 fc fe ff ff 7e ?? 00 00 0a 2d 08 20 ?? 05 3b b4 25 2b 06}  //weight: 4, accuracy: Low
        $x_1_2 = "$ecb3711a-e896-4e7c-afb3-3cf202672cc9" ascii //weight: 1
        $x_1_3 = "cryptload.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_NK_2147914185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.NK!MTB"
        threat_id = "2147914185"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 36 00 00 01 13 03 20 ?? 00 00 00 28 ?? 00 00 06 39 ?? fe ff ff 26 20 ?? 00 00 00 38 ?? fe ff ff 02 16 11 03 16 02 8e 69 1f 10 da}  //weight: 3, accuracy: Low
        $x_1_2 = "sagepromostar_instrument2.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_QQAA_2147915050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.QQAA!MTB"
        threat_id = "2147915050"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 08 06 6f ?? 00 00 0a 08 07 6f ?? 00 00 0a 08 17 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 13 04 de 14}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SPZF_2147915072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SPZF!MTB"
        threat_id = "2147915072"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 02 73 50 00 00 0a 0c 08 07 16 73 51 00 00 0a 0d 73 52 00 00 0a 13 04}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_RJAA_2147915864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.RJAA!MTB"
        threat_id = "2147915864"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 06 02 06 91 66 d2 9c 02 06 8f 22 00 00 01 25 71 22 00 00 01 20 84 00 00 00 59 d2 81 22 00 00 01 02 06 8f 22 00 00 01 25 71 22 00 00 01 1f 67 58 d2 81 22 00 00 01 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_STAA_2147917154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.STAA!MTB"
        threat_id = "2147917154"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 13 04 73 ?? 00 00 0a 0b 07 11 04 17 73 ?? ?? 00 0a 0c 02 28 ?? ?? 00 06 0d 08 09 16 09 8e 69 6f ?? 00 00 0a 07 13 05 de 0e}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_KAH_2147917508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.KAH!MTB"
        threat_id = "2147917508"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 11 04 09 6f ?? 00 00 0a 13 05 12 05 28 ?? 00 00 0a 16 fe 01 13 06 11 06 2c 0b 00 08 6f ?? 00 00 0a 13 07 2b 39 08 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 11 04 17 58 13 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_TFAA_2147917673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.TFAA!MTB"
        threat_id = "2147917673"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 2d e3 16 2d 02 2b 1d 2b 66 07 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 08 18 25 2c 0c 58 0c 08 16 2d d2 07 6f ?? 00 00 0a 15 2c ee 32 d4 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_TKAA_2147917936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.TKAA!MTB"
        threat_id = "2147917936"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 16 0c 38 19 00 00 00 06 07 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 08 18 58 0c 08 07 6f ?? 00 00 0a 32 de}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_TQAA_2147918294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.TQAA!MTB"
        threat_id = "2147918294"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0d 2b 13 00 08 09 08 09 91 20 ?? ?? 00 00 59 d2 9c 00 09 17 58 0d 09 08 8e 69 fe 04 13 04 11 04 2d e1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_UMAA_2147919644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.UMAA!MTB"
        threat_id = "2147919644"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0d 09 08 17 73 ?? 00 00 0a 13 04 2b 19 2b 1b 16 2b 1b 8e 69 2b 1a 09 6f ?? 00 00 0a 13 05 16 2d f5 1a 2c e7 de 34 11 04 2b e3 06 2b e2 06 2b e2 6f ?? 00 00 0a 2b df}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_VNAA_2147920342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.VNAA!MTB"
        threat_id = "2147920342"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 0c 2b 1a 06 08 02 08 91 07 08 07 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e0}  //weight: 4, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SEAA_2147920719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SEAA!MTB"
        threat_id = "2147920719"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "V.i.r.t.u.a.l.A.l.l.o.c" wide //weight: 2
        $x_3_2 = "V.i.r.t.u.a.l.P.r.o.t.e.c.t" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_KAAE_2147920820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.KAAE!MTB"
        threat_id = "2147920820"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 11 05 6f ?? 00 00 0a 07 33 1e 09 17 58 0d 09 08 17 58 33 0e 06 11 04 11 05 11 04 59 6f ?? 00 00 0a 2a 11 05 17 58 13 04 11 05 17 58 13 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_KAF_2147924229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.KAF!MTB"
        threat_id = "2147924229"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 91 02 07 02 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 28 ?? 00 00 06 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SL_2147924506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SL!MTB"
        threat_id = "2147924506"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 72 01 00 00 70 6f 10 00 00 0a 0a dd 0d 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SCCF_2147924560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SCCF!MTB"
        threat_id = "2147924560"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {07 03 04 6f ?? 00 00 0a 0c 02 73 ?? 00 00 0a 0d 09 08 16 73 ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 26 de 2a 11 04}  //weight: 3, accuracy: Low
        $x_2_2 = "CreateDecryptor" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AACA_2147924862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AACA!MTB"
        threat_id = "2147924862"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 06 02 06 91 66 d2 9c 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 58 59 d2 81 ?? 00 00 01 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 44 59 d2 81 ?? 00 00 01 00 06 17 58 0a 06 02 8e 69 fe 04 13 0b 11 0b 3a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SCXF_2147924920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SCXF!MTB"
        threat_id = "2147924920"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 03 04 6f ?? 00 00 0a 0b 02 73 ?? 00 00 0a 0c 08 07 16 73 ?? 00 00 0a 0d 02 8e 69 8d 1c 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 11 04 11 05 28 ?? 00 00 2b 28 ?? 00 00 2b 13 06 de 28}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AKCA_2147925207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AKCA!MTB"
        threat_id = "2147925207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 06 8f 26 00 00 01 25 71 26 00 00 01 1f ?? 59 d2 81 26 00 00 01 08 20}  //weight: 3, accuracy: Low
        $x_2_2 = {02 06 8f 26 00 00 01 25 71 26 00 00 01 1f ?? 59 d2 81 26 00 00 01 08}  //weight: 2, accuracy: Low
        $x_1_3 = {02 06 02 06 91 66 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AMX_2147925329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AMX!MTB"
        threat_id = "2147925329"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 02 06 91 66 d2 9c [0-255] 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 59 d2 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ARDA_2147926447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ARDA!MTB"
        threat_id = "2147926447"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {03 11 00 91 13 02 38 ?? ff ff ff 03 8e 69 17 59 13 03 38 ?? ff ff ff 03 2a 03 11 03 11 02 9c 38 4d 00 00 00 11 00 11 03}  //weight: 3, accuracy: Low
        $x_2_2 = {03 11 00 03 11 03 91 9c 20 04 00 00 00 fe 0e 01 00 38 ?? ff ff ff 16 13 00}  //weight: 2, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_ANFA_2147927984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ANFA!MTB"
        threat_id = "2147927984"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 07 11 04 6f ?? 00 00 0a 28 ?? 01 00 06 13 1b 28 ?? 01 00 06 28 ?? 01 00 06 28 ?? 01 00 06 61 28 ?? 01 00 06 33 0e 28 ?? 01 00 06 13 1b fe ?? ?? 00 00 01 58 00 73 ?? 00 00 0a 13 08}  //weight: 3, accuracy: Low
        $x_2_2 = {11 08 11 0a 28 ?? 01 00 06 13 1d 28 ?? 01 00 06 28 ?? 01 00 06 28 ?? 01 00 06 61 28 ?? 01 00 06 33 0e 28 ?? 01 00 06 13 1d fe ?? ?? 00 00 01 58 00 11 0a 8e 69 6f ?? 00 00 0a 25 13 0b 28 ?? 01 00 06 13 1e 28 ?? 01 00 06 28 ?? 01 00 06 28 ?? 01 00 06 61 28 ?? 01 00 06 33 0e 28 ?? 01 00 06 13 1e fe ?? ?? 00 00 01 58 00 3d ?? ff ff ff 11 09 6f ?? 00 00 0a 13 06 de 0c}  //weight: 2, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AWGA_2147928715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AWGA!MTB"
        threat_id = "2147928715"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 11 08 7e 08 00 00 04 11 08 91 28 ?? 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 11 08 28 ?? 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 8e 69 5d 91 61 d2 9c 00 11 08 17 58 13 08 11 08 7e 08 00 00 04 8e 69 fe 04 13 09 11 09 2d b5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SSUB_2147930040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SSUB!MTB"
        threat_id = "2147930040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 00 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0d 09 04 16 04 8e 69 6f ?? 00 00 0a 13 04 de 16}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SGUD_2147930117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SGUD!MTB"
        threat_id = "2147930117"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 05 11 05 09 07 08 6f ?? 00 00 0a 17 73 3f 00 00 0a 13 06 11 06 11 04 16 11 04 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 28 ?? 00 00 0a 13 07 de 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_GA_2147931815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.GA!MTB"
        threat_id = "2147931815"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "YzMyMTVmZTM3MmQwNWZjMDkxNzY2NTRiZGEyYzhhMDIyZjY2ZTg1MDBkN2U4OWNmYTliM2NmNTkzYjY5MjVmZQ==" wide //weight: 3
        $x_1_2 = "GetDelegateForFunctionPointer" wide //weight: 1
        $x_2_3 = "file:///" wide //weight: 2
        $x_1_4 = "{11111-22222-10009-11111}" wide //weight: 1
        $x_1_5 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_1_6 = "{11111-22222-20001-00001}" wide //weight: 1
        $x_1_7 = "{11111-22222-20001-00002}" wide //weight: 1
        $x_1_8 = "{11111-22222-30001-00001}" wide //weight: 1
        $x_1_9 = "{11111-22222-30001-00002}" wide //weight: 1
        $x_1_10 = "{11111-22222-40001-00001}" wide //weight: 1
        $x_1_11 = "{11111-22222-40001-00002}" wide //weight: 1
        $x_1_12 = "$this.SnapToGrid" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_MBWQ_2147931876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.MBWQ!MTB"
        threat_id = "2147931876"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "System.Diagnostics.StackTrace" wide //weight: 2
        $x_1_2 = {61 00 4f 00 79 00 48 00 4e 00 00 47 62 00 61}  //weight: 1, accuracy: High
        $x_1_3 = {6c 00 64 00 72 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SWA_2147932324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SWA!MTB"
        threat_id = "2147932324"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 06 08 09 6f 4c 00 00 0a 13 04 08 11 04 58 0c 09 11 04 59 0d 09 16 3d e4 ff ff ff dd 0d 00 00 00 07 39 06 00 00 00 07 6f 8a 00 00 0a dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SFUD_2147932394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SFUD!MTB"
        threat_id = "2147932394"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 32 16 2d e4 2b 34 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0b de 38 06 2b cf 28 ?? 00 00 0a 2b cf 6f ?? 00 00 0a 2b ca 06 2b cc 28 ?? 00 00 0a 2b cc 6f ?? 00 00 0a 2b c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AQKA_2147932791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AQKA!MTB"
        threat_id = "2147932791"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 13 36 02 11 31 91 13 36 11 36 11 34 16 6f ?? 00 00 0a 61 d2 13 36 02 11 31 11 36 9c 11 31 17 58 13 31}  //weight: 3, accuracy: Low
        $x_2_2 = {13 32 11 32 11 2b 11 2e 91 6f ?? 00 00 0a 11 2b 11 2e 11 2b 11 2d 91 9c 11 2b 11 2d 11 32 16 6f ?? 00 00 0a 9c 11 2b 11 2d 91 11 2b 11 2e 91 58 7e ?? 00 00 04 28 ?? 03 00 06 11 2f 7e ?? 00 00 04 28 ?? 03 00 06 7e ?? 00 00 04 28 ?? 03 00 06 7e ?? 00 00 04 28 ?? 03 00 06 5d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SHLZ_2147933418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SHLZ!MTB"
        threat_id = "2147933418"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 19 8d 40 00 00 01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SAS_2147934107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SAS!MTB"
        threat_id = "2147934107"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 0b 00 00 06 72 a1 00 00 70 7e 03 00 00 04 6f 14 00 00 0a 74 01 00 00 1b}  //weight: 2, accuracy: High
        $x_2_2 = {11 01 11 03 11 00 11 03 91 72 61 00 00 70 28 03 00 00 0a 59 d2 9c 20 05 00 00 00 7e 10 00 00 04 7b 52 00 00 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SEA_2147934108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SEA!MTB"
        threat_id = "2147934108"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 0a 1e 7e 66 01 00 04 28 3e 04 00 06 17 8d 22 00 00 01 7e 67 01 00 04 28 42 04 00 06 28 16 00 00 06 7e 56 01 00 04 28 fe 03 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_SAT_2147935238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.SAT!MTB"
        threat_id = "2147935238"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 32 00 00 0a 25 80 ?? ?? ?? 04 28 02 00 00 2b 28 03 00 00 2b 16 94 28 35 00 00 0a}  //weight: 2, accuracy: Low
        $x_2_2 = "FromBase64String" ascii //weight: 2
        $x_2_3 = "CreateDecryptor" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AYNA_2147935933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AYNA!MTB"
        threat_id = "2147935933"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 11 08 18 5b 06 72 61 00 00 70 18 8d 1c 00 00 01 25 16 d0 30 00 00 01 28 ?? 00 00 0a a2 25 17 d0 28 00 00 01 28 ?? 00 00 0a a2 6f ?? 00 00 0a 16 8c 28 00 00 01 18 8d 16 00 00 01 25 16 02 11 08 07 6f ?? 00 00 0a a2 25 17 08 8c 28 00 00 01 a2 6f ?? 00 00 0a a5 31 00 00 01 9c 11 08 18 58 13 08 11 08 11 04 32 97}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_APSA_2147940528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.APSA!MTB"
        threat_id = "2147940528"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 11 06 09 11 06 91 06 11 06 91 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 32 e5}  //weight: 5, accuracy: High
        $x_2_2 = {11 04 08 59 02 8e 69 58 02 8e 69 5d 13 05 09 11 05 02 11 04 91 9c 11 04 17 58 13 04 11 04 02 8e 69 32 dd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AHDB_2147949833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AHDB!MTB"
        threat_id = "2147949833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 2d 0b 72 ?? ?? 00 70 73 ?? 00 00 0a 7a 73 ?? 00 00 0a 0a 02 7b ?? 00 00 04 0b 16 0c 07 12 02 28 ?? 00 00 0a 73 ?? 00 00 0a 0d 09 02 7b ?? 00 00 04 02 7b ?? 00 00 04 6f ?? 00 00 0a 13 04 06 11 04 17 73 ?? 00 00 0a 13 05 03 11 05 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 06 16 6a 6f ?? 00 00 0a de 2c}  //weight: 5, accuracy: Low
        $x_5_2 = {0a 13 07 73 ?? 00 00 0a 13 08 11 08 11 07 11 05 11 06 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 09 11 09 06 16 06 8e 69 6f ?? 00 00 0a 11 08 6f ?? 00 00 0a 13 0a de 3f}  //weight: 5, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Injuke_ATEB_2147951975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.ATEB!MTB"
        threat_id = "2147951975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 05 91 13 06 06 7b ?? 00 00 04 07 11 05 07 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 11 06 61 d2 6f ?? 00 00 0a 00 00 11 05 17 58 13 05 11 05 08 28 ?? 00 00 2b fe 04 13 07 11 07 2d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AZFB_2147953319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AZFB!MTB"
        threat_id = "2147953319"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 16 07 1f 0f 1f 10 1d 2d 61 26 26 26 26 26 26 7e ?? 00 00 04 06 07 1d 2d 58 26 26 26 7e ?? 00 00 04 06 18 28 ?? ?? 00 06 7e ?? 00 00 04 06 19 28 ?? ?? 00 06 7e ?? 00 00 04 06 28 ?? ?? 00 06 0d 7e ?? 00 00 04 09 03 16 03 8e 69 28 ?? ?? 00 06 2a 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_AYMB_2147959199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.AYMB!MTB"
        threat_id = "2147959199"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0b 2b 15 06 07 8f ?? 00 00 01 25 47 7e ?? 00 00 04 61 d2 52 07 17 58 0b 07 06 8e 69 32 e5}  //weight: 2, accuracy: Low
        $x_5_2 = {0a 0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 03 04 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 02 16 02 8e 69 28 ?? 00 00 0a 03 16 03 8e 69 28 ?? 00 00 0a 04 16 04 8e 69 28 ?? 00 00 0a 0c de 14}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injuke_BAA_2147959385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injuke.BAA!MTB"
        threat_id = "2147959385"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 16 0b 2b 15 06 07 8f 1a 00 00 01 25 47 7e 02 00 00 04 61 d2 52 07 17 58 0b 07 06 8e 69 32 e5 28 ?? 00 00 0a 06 6f ?? 00 00 0a 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

