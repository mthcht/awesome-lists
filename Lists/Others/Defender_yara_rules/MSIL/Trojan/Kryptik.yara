rule Trojan_MSIL_Kryptik_R_2147742236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.R!ibt"
        threat_id = "2147742236"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 18 0c d0 09 00 00 01 28 ?? 00 00 0a ?? 73 ?? 00 00 0a 06 08 60 14 04 17 8d 01 00 00 01 0d 09 16 03 a2 09 28 13 00 00 0a 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {02 00 00 11 d0 25 00 00 01 28 2e 00 00 0a 72 ba 0d 00 70 20 14 01 00 00 14 04 17 8d 02 00 00 01 0a 06 16 03 a2 06 28 2f 00 00 0a 2a}  //weight: 1, accuracy: High
        $x_2_3 = {08 18 5b 03 08 18 6f ?? ?? ?? ?? 1f 10 28 ?? ?? ?? ?? 9c 2b 1b 07 09 03 08 18 6f ?? ?? ?? ?? 1f 10 28 ?? ?? ?? ?? 06 09 06 8e 69 5d 91 61 d2 9c 08 18 58 0c 08 03 6f ?? ?? ?? ?? 32 b6}  //weight: 2, accuracy: Low
        $x_2_4 = {08 18 5b 03 08 18 6f ?? ?? ?? ?? 1f 10 28 ?? ?? ?? ?? 9c 2b 22 08 18 5b 1f 10 59 0d 06 09 03 08 18 6f ?? ?? ?? ?? 1f 10 28 ?? ?? ?? ?? 07 09 07 8e 69 5d 91 61 d2 9c 08 18 58 0c 08 03 6f ?? ?? ?? ?? 32 b6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Kryptik_J_2147742625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.J!ibt"
        threat_id = "2147742625"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MP5_SMG_GunGuru_" wide //weight: 1
        $x_1_2 = "Erik Humphrey's Maze Game" wide //weight: 1
        $x_5_3 = "HumphreyMaze.exe" wide //weight: 5
        $x_5_4 = "HumphreyXMaze.exe" wide //weight: 5
        $x_3_5 = {01 0d 09 09 47 02 08 1f 10 5d 91 61 d2 52}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Kryptik_XJ_2147743743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.XJ!ibt"
        threat_id = "2147743743"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 de 03 26 de 00 2a 10 00 28 ?? 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {06 dd 06 00 00 00 26 dd 00 00 00 00 2a 15 00 28 ?? 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = {0a 14 14 6f ?? 00 00 0a 26 0a 00 6f ?? 00 00}  //weight: 1, accuracy: Low
        $x_5_4 = {fe 0e 00 00 fe 0c 00 00 28 1b 00 00 06 dd 06 00 00 00 26 dd 00 00 00 00 2a 30 00 28 ?? 00 00 06}  //weight: 5, accuracy: Low
        $x_5_5 = {06 de 03 26 de 00 2a 30 00 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 06 28 ?? 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Kryptik_SK_2147744259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.SK!eml"
        threat_id = "2147744259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SimpleSchool.exe" wide //weight: 1
        $x_1_2 = "SimpleSchool.Properties.Resources" wide //weight: 1
        $x_1_3 = "courseDATestToolStripMenuItem" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_SK_2147744259_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.SK!eml"
        threat_id = "2147744259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GuessTheAnimal.exe" wide //weight: 1
        $x_1_2 = "TowerCorner.exe" wide //weight: 1
        $x_1_3 = "CalculatorBinaries.exe" wide //weight: 1
        $x_1_4 = "AmadeusZeus.exe" wide //weight: 1
        $x_1_5 = "AnimalGames.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Kryptik_SK_2147744259_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.SK!eml"
        threat_id = "2147744259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 76 69 64 69 61 43 61 74 61 6c 79 73 74 73 2e 70 64 62 58 00 43 3a 5c 55 73 65 72 73 5c 53 61 6b 6f 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 4e 76 69 64 69 61 43 61 74 61 6c 79 73 74 73 5c 4e 76 69 64 69 61 43 61 74 61 6c 79 73 74 73 5c 6f 62 6a 5c 44 65 62 75 67}  //weight: 1, accuracy: Low
        $x_1_2 = "c:\\temp\\Assembly.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_A_2147744801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.A!MTB"
        threat_id = "2147744801"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 7e 5a 00 00 04 25 2d 17 26 7e 59 00 00 04 fe 06 2c 00 00 06 73 ab 00 00 0a 25 80 5a 00 00 04 7d 56 00 00 04 02 7e 5b 00 00 04 25 2d 17 26 7e 59 00 00 04 fe 06 2d 00 00 06 73 ac 00 00 0a 25 80 5b}  //weight: 10, accuracy: High
        $x_1_2 = "qakeRkpq" ascii //weight: 1
        $x_1_3 = "tazcImj52" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_CS_2147745368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.CS!eml"
        threat_id = "2147745368"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KurdishCoderProducts" ascii //weight: 1
        $x_1_2 = "RazerInsider" ascii //weight: 1
        $x_1_3 = "RazerPanel.Properties.Resources" wide //weight: 1
        $x_1_4 = "RazerPanel.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_FI_2147775124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.FI!MTB"
        threat_id = "2147775124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 04 13 05 11 05 1f 41 32 06 11 05 1f 4d}  //weight: 10, accuracy: High
        $x_10_2 = {11 05 1f 4e 32 06 11 05 1f 5a 31 14 11 05 1f}  //weight: 10, accuracy: High
        $x_2_3 = "CreateInstance" ascii //weight: 2
        $x_2_4 = "FromBase64" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_FI_2147775124_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.FI!MTB"
        threat_id = "2147775124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 82 d2 52 26 06 47 06 62 00 e7 05 53 00 c1 79 46 06 56 00 26 06 4a 00 43 06 47 06 2d 06}  //weight: 1, accuracy: High
        $x_1_2 = "In$J$ct0r" ascii //weight: 1
        $x_1_3 = {57 00 7e 82 7e 82 86 06 27 06 58 00 4f 00 6c 9a 4e 30 4c 00 4d 00 d6 05 d4 05 51 00 51 00}  //weight: 1, accuracy: High
        $x_1_4 = "kWJGgxWm8LEUQ58EH1EBeHypuS" ascii //weight: 1
        $x_1_5 = "Ap$p$ex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_FB_2147775125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.FB!MTB"
        threat_id = "2147775125"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 03 11 05 11 0c 28 [0-16] 13 0e 02 11 0d 11 0e 28 [0-4] 13 0f 11 0f 13 10 11 10 2c 2c 09 19 8d [0-4] 25 16 12 0d 28 [0-4] 9c 25 17 12 0d 28 [0-4] 9c 25 18 12 0d 28 [0-13] 11 0c 17 d6 13 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_ZE_2147775689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.ZE!MTB"
        threat_id = "2147775689"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {27 09 27 09 11 09 2b 09 2d 09 18 09 20 09 2f 09 0f 09 2b 09 1b 09 18 09 2b 09 2f 09}  //weight: 10, accuracy: High
        $x_10_2 = {08 09 9a 13 04 00 11 04 28 [0-9] 75 1a ce 41 59 28 [0-4] b7 13 05 06 11 05 28 [0-9] 26 00 09 17 58 0d 09 08 8e 69 32 c8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_ST_2147775913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.ST!MTB"
        threat_id = "2147775913"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0b 07 1f 61 32 0a 07 1f 7a fe 02 16 fe 01 2b 01 16 0c 08 2c 1e 07 1f 6d fe 02 16 fe 01 0d 09 2c 08 07 1f 0d d6 0b 00 2b 07 00 07 1f 0d da 0b 00 00 2b 34 07 1f 41 32 0a}  //weight: 10, accuracy: High
        $x_10_2 = {07 1f 5a fe 02 16 fe 01 2b 01 16 13 04 11 04 2c 1e 07 1f 4d fe 02 16 fe 01 13 05 11 05 2c 08 07 1f 0d d6 0b 00 2b 07 00 07 1f 0d da 0b 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_TB_2147776151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.TB!MTB"
        threat_id = "2147776151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {91 06 07 06 8e 69 6a 5d 28 [0-4] 28 [0-4] 91 61 02 07 17 6a 58 20 [0-4] 6a 5d 28 [0-9] 91 59 6a 20 [0-4] 6a 58 20 [0-4] 6a 5d d2 9c ?? 07 17 6a 58 0b 07}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_KI_2147776158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.KI!MTB"
        threat_id = "2147776158"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 11 04 9a 13 05 11 05 28 [0-4] 23 00 00 00 00 00 80 73 40 59 28 [0-4] b7 13 06 07 11 06 28 [0-4] 6f [0-4] 26 00 11 04 17 d6 13 04 11 04 09 8e 69 fe 04 13 07 11 07 2d bf}  //weight: 10, accuracy: Low
        $x_2_2 = "FromBase64String" ascii //weight: 2
        $x_2_3 = "CreateInstance" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_SL_2147776159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.SL!MTB"
        threat_id = "2147776159"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 07 14 72 [0-4] 18 8d [0-4] 25 16 1e 8d [0-4] 25 d0 [0-4] 28 [0-4] a2 25 17 1e}  //weight: 10, accuracy: Low
        $x_10_2 = {a2 14 14 28 [0-9] 0c 08 14 72 [0-4] 19 8d [0-4] 25 16 02 a2 25 17 16 8c [0-4] a2 25 18 20 [0-9] a2 14 14 28 [0-9] 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_2_3 = "CreateDecryptor" ascii //weight: 2
        $x_2_4 = "LateBinding" ascii //weight: 2
        $x_2_5 = "TransformFinalBlock" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_ET_2147776188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.ET!MTB"
        threat_id = "2147776188"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 05 11 0a ?? 22 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b ?? 22 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f [0-4] 26}  //weight: 10, accuracy: Low
        $x_1_2 = "IDbCommand" ascii //weight: 1
        $x_1_3 = "OleDbCommand" ascii //weight: 1
        $x_1_4 = "WebResponse" ascii //weight: 1
        $x_1_5 = "GetResponse" ascii //weight: 1
        $x_1_6 = "GetObjectValue" ascii //weight: 1
        $x_1_7 = "GetResourceString" ascii //weight: 1
        $x_1_8 = "CompareString" ascii //weight: 1
        $x_1_9 = "ToString" ascii //weight: 1
        $x_1_10 = "OleDbConnection" ascii //weight: 1
        $x_1_11 = "StringBuilder" ascii //weight: 1
        $x_1_12 = "IDataAdapter" ascii //weight: 1
        $x_1_13 = "IDbDataAdapter" ascii //weight: 1
        $x_1_14 = "OleDbDataAdapter" ascii //weight: 1
        $x_1_15 = "WebRequest" ascii //weight: 1
        $x_1_16 = "ContainsKey" ascii //weight: 1
        $x_1_17 = "set_TransparencyKey" ascii //weight: 1
        $x_1_18 = "ExecuteNonQuery" ascii //weight: 1
        $x_1_19 = "System.Security" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 17 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Kryptik_TU_2147776189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.TU!MTB"
        threat_id = "2147776189"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0b 07 28 [0-4] 03 6f [0-4] 6f [0-4] 0c 06 08 6f [0-5] 06 18 6f [0-5] 06 6f [0-4] 02 16 02 8e 69 6f [0-4] 0d 09 13 04 2b 00 11 04 2a}  //weight: 10, accuracy: Low
        $x_10_2 = {69 00 a4 06 2e 06 27 06 54 00 35 06 49 06 4a 04 35 04 45 06 09 54 55 00 0c 20 34 06 46 06 09 54 17 5f}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_TR_2147776190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.TR!MTB"
        threat_id = "2147776190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 00 03 28 [0-4] 72 [0-4] 6f [0-4] 0b 07 19 8d [0-4] 25 16 7e [0-4] a2 25 17 7e [0-4] a2 25 18 72 [0-4] a2 28 [0-4] 26 20 [0-4] 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "FromBase64CharArray" ascii //weight: 2
        $x_2_3 = "WSTRBufferMarshaler" ascii //weight: 2
        $x_2_4 = "NewLateBinding" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_UC_2147776230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.UC!MTB"
        threat_id = "2147776230"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 20 00 03 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 13 21 11 21 19 8d ?? ?? ?? ?? 25 16 7e ?? ?? ?? ?? a2 25 17 7e ?? ?? ?? ?? a2 25 18 72 ?? ?? ?? ?? a2 28 ?? ?? ?? ?? 26 20 ?? ?? ?? ?? 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "FromBase64CharArray" ascii //weight: 2
        $x_2_3 = "CreateInstance" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_AS_2147776231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.AS!MTB"
        threat_id = "2147776231"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 20 00 03 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 13 21 11 21 19 8d ?? ?? ?? ?? 25 16 7e ?? ?? ?? ?? a2 25 17 7e ?? ?? ?? ?? a2 25 18 72 ?? ?? ?? ?? a2 28 ?? ?? ?? ?? 26 20 ?? ?? ?? ?? 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "CreateInstance" ascii //weight: 2
        $x_2_3 = "Activator" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_WR_2147776232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.WR!MTB"
        threat_id = "2147776232"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6e 17 6a d6 20 [0-4] 6a 5f b8 0c 09 11 05 08 84 95 d7 6e 20 [0-4] 6a 5f b8 0d 11 05 08 84 95 13 04 11 05 08 84 11 05 09 84 95 9e 11 05 09 84 11 04}  //weight: 10, accuracy: Low
        $x_10_2 = {9e 11 06 11 07 02 11 07 91 11 05 11 05 08 84 95 11 05 09 84 95 d7 6e 20 [0-4] 6a 5f b7 95 61 86 9c 11 07 17 d6 13 07 11 07 11 0a 31 9b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_WR_2147776232_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.WR!MTB"
        threat_id = "2147776232"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 16 09 28 [0-4] 28 ?? ?? ?? ?? a2 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 13 04 11 04 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 07 6f ?? ?? ?? ?? 18 14 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 13 05 11 05 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 08 6f ?? ?? ?? ?? 17 18 8d ?? ?? ?? ?? 25 16 72}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CallByName" ascii //weight: 1
        $x_1_4 = "GetObjectValue" ascii //weight: 1
        $x_1_5 = "StrReverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_UN_2147776470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.UN!MTB"
        threat_id = "2147776470"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 21 11 21 19 8d ?? ?? ?? ?? 25 16 7e ?? ?? ?? ?? a2 25 17 7e ?? ?? ?? ?? a2 25 18 72 ?? ?? ?? ?? a2 28 ?? ?? ?? ?? 26 20 ?? ?? ?? ?? 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "CreateInstance" ascii //weight: 2
        $x_2_3 = "Activator" ascii //weight: 2
        $x_2_4 = "LateCall" ascii //weight: 2
        $x_2_5 = "NewLateBinding" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_UL_2147776471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.UL!MTB"
        threat_id = "2147776471"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1f 61 32 0a 06 1f 7a fe 02 16 fe 01 2b 01 16 0b 07 2c 1d [0-2] 06 1f 6d fe 02 0c 08 2c 09 [0-2] 06 1f 0d 59 0a [0-2] 2b 07 [0-2] 06 1f 0d 58 0a}  //weight: 10, accuracy: Low
        $x_10_2 = {16 0d 09 2c 1d [0-2] 06 1f 4d fe 02 13 04 11 04 2c 09 [0-2] 06 1f 0d 59 0a [0-2] 2b 07 [0-2] 06 1f 0d 58 0a [0-2] 06 d1 13 05 2b 00 11 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_VC_2147776485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.VC!MTB"
        threat_id = "2147776485"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 07 19 8d ?? ?? ?? ?? 25 16 7e ?? ?? ?? ?? a2 25 17 7e ?? ?? ?? ?? a2 25 18 72 ?? ?? ?? ?? a2 28 ?? ?? ?? ?? 26 20 ?? ?? ?? ?? 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_10_2 = {0d 07 09 6f ?? ?? ?? ?? ?? 07 18 6f ?? ?? ?? ?? ?? 07 6f ?? ?? ?? ?? 03 16 03 8e 69 6f ?? ?? ?? ?? 13 04 11 04 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_2_3 = "FromBase64" ascii //weight: 2
        $x_2_4 = "WSTRBufferMarshaler" ascii //weight: 2
        $x_2_5 = "CreateInstance" ascii //weight: 2
        $x_2_6 = "Activator" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Kryptik_TF_2147776766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.TF!MTB"
        threat_id = "2147776766"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 17 d6 18 28 [0-22] 02 18 d6 19 28 [0-22] 02 19 d6 1a 28 [0-22] 02 1a d6 1b 28 [0-22] 02 1b d6 1c}  //weight: 10, accuracy: Low
        $x_2_2 = "GetExportedTypes" ascii //weight: 2
        $x_2_3 = "CreateDelegate" ascii //weight: 2
        $x_2_4 = "WebRequest" ascii //weight: 2
        $x_2_5 = "WebResponse" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_UR_2147776767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.UR!MTB"
        threat_id = "2147776767"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0b 07 28 [0-4] 03 6f [0-9] 0c 06 08 6f [0-5] 06 18 6f [0-5] 06 6f [0-4] 02 16 02 8e 69 6f [0-4] 0d 09 13 04 2b 00 11 04 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "GetExportedTypes" ascii //weight: 2
        $x_2_3 = "CreateInstance" ascii //weight: 2
        $x_2_4 = "Activator" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_WA_2147776901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.WA!MTB"
        threat_id = "2147776901"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 6e 17 6a d6 20 [0-4] 6a 5f b8 0c 09 11 05 08 84 95 d7 6e 20 [0-4] 6a 5f b8 0d 11 05 08 84 95 13 04 11 05 08 84 11 05 09 84 95 9e}  //weight: 10, accuracy: Low
        $x_10_2 = {11 05 09 84 11 04 9e 11 06 11 08 03 11 08 91 11 05 11 05 08 84 95 11 05 09 84 95 d7 6e 20 [0-4] 6a 5f b7 95 61 86 9c 11 08 17 d6 13 08 11 08 11 07 31 9b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_WB_2147776923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.WB!MTB"
        threat_id = "2147776923"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {1f 7a fe 02 16 fe 01 2b 01 16 13 61 11 61 2c 1f 00 06 1f 6d fe 02 13 62 11 62 2c 09 00 06 1f 0d 59 0a 00 2b 07 00 06 1f 0d 58 0a}  //weight: 10, accuracy: High
        $x_10_2 = {2b 33 06 1f 41 32 0a 06 1f 5a fe 02 16 fe 01 2b 01 16 13 63 11 63 2c 1d 00 06 1f 4d fe 02 13 64 11 64 2c 09 00 06 1f 0d 59 0a 00 2b 07}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_VX_2147776924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.VX!MTB"
        threat_id = "2147776924"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 02 07 28 [0-4] 25 26 03 07 03 28 [0-4] 25 26 5d 28 [0-4] 25 26 61 d1 28 [0-4] 25 26 26 07 17 58 0b 07 02 28 [0-4] 25 26}  //weight: 10, accuracy: Low
        $x_2_2 = "FromBase64" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_VU_2147776925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.VU!MTB"
        threat_id = "2147776925"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {19 8d 0d 00 00 01 25 16 7e [0-2] 00 00 04 a2 25 17 7e [0-2] 00 00 04 a2 25 18 72 [0-3] 70 a2}  //weight: 10, accuracy: Low
        $x_2_2 = "FromBase64" ascii //weight: 2
        $x_2_3 = "WSTRBufferMarshaler" ascii //weight: 2
        $x_2_4 = "CreateInstance" ascii //weight: 2
        $x_2_5 = "Activator" ascii //weight: 2
        $x_2_6 = "FallbackBuffer" ascii //weight: 2
        $x_2_7 = "CryptoServiceProvider" ascii //weight: 2
        $x_2_8 = "TransformFinalBlock" ascii //weight: 2
        $x_2_9 = "CreateDecryptor" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Kryptik_WO_2147777002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.WO!MTB"
        threat_id = "2147777002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1f 61 32 0a 06 1f 7a fe 02 16 fe 01 2b 01 16 0b 07 2c [0-2] 06 1f 6d fe 02 0c 08 2c [0-2] 06 1f 0d 59 0a [0-2] 2b [0-2] 06 1f 0d 58 0a}  //weight: 10, accuracy: Low
        $x_10_2 = {16 0d 09 2c [0-2] 06 1f 4d fe 02 13 04 11 04 2c [0-2] 06 1f 0d 59 0a [0-2] 2b [0-2] 06 1f 0d 58 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_WP_2147777003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.WP!MTB"
        threat_id = "2147777003"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0b 1e 8d [0-4] 0c 07 28 [0-4] 03 6f [0-9] 0d 09 16 08 16 1e 28 [0-5] 06 08 6f [0-5] 06 18 6f [0-5] 06 6f [0-4] 02 16 02 8e 69}  //weight: 10, accuracy: Low
        $x_1_2 = "TransformFinalBlock" ascii //weight: 1
        $x_1_3 = "GetExportedTypes" ascii //weight: 1
        $x_1_4 = "CryptoServiceProvider" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_WF_2147777004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.WF!MTB"
        threat_id = "2147777004"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 31 03 09 28 [0-4] 04 09 04 6f [0-4] 5d 17 d6 28 [0-4] da 13 04 07 11 04 28 [0-4] 28 [0-4] 28 [0-4] 0b 09 17 d6 0d 09 08 31 cb}  //weight: 10, accuracy: Low
        $x_10_2 = {0a 0c 08 28 [0-4] 03 6f [0-4] 6f [0-4] 0d 07 09 6f [0-5] 07 18 6f [0-5] 07 6f [0-4] 04 16 04 8e 69 6f [0-4] 13 04 11 04 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_2_3 = "CreateDecryptor" ascii //weight: 2
        $x_2_4 = "InvokeMember" ascii //weight: 2
        $x_2_5 = "TransformFinalBlock" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Kryptik_XG_2147777306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.XG!MTB"
        threat_id = "2147777306"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 11 05 02 11 05 18 5a 18 6f [0-4] 1f 10 28 [0-4] 9c 00 11 05 17 58 13 05 11 05 06 fe 04 13 06 11 06 2d d7}  //weight: 10, accuracy: Low
        $x_2_2 = "CallByName" ascii //weight: 2
        $x_2_3 = "LateBinding" ascii //weight: 2
        $x_2_4 = {49 00 6e 00 a4 06 c6 06 6f 00 6b 00 65 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_YD_2147777404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.YD!MTB"
        threat_id = "2147777404"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 6e 17 6a d6 20 [0-4] 6a 5f b8 0d 11 04 11 06 09 84 95 d7 6e 20 [0-4] 6a 5f b8 13 04 11 06 09 84 95 13 05 11 06 09 84 11 06 11 04 84 95 9e 11 06 11 04 84}  //weight: 10, accuracy: Low
        $x_10_2 = {11 05 9e 11 07 07 28 [0-4] 03 07 28 [0-4] 91 11 06 11 06 09 84 95 11 06 11 04 84 95 d7 6e 20 [0-4] 6a 5f b7 95 61 86 9c 07 11 08 12 01 28 [0-4] 13 0a 11 0a 2d 8a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_JR_2147777584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.JR!MTB"
        threat_id = "2147777584"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 06 07 16 07 8e 69 6f [0-4] 26 07 72 [0-4] 28 [0-4] 0b 07 28 [0-4] 6f [0-4] 14 14 6f [0-4] 26 de 0a}  //weight: 10, accuracy: Low
        $x_2_2 = "#PASSWORD" ascii //weight: 2
        $x_2_3 = "get_EntryPoint" ascii //weight: 2
        $x_2_4 = "Invoke" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_YK_2147777585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.YK!MTB"
        threat_id = "2147777585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 5f 88 13 04 11 05 08 11 04 84 95 d7 6e 20 [0-4] 6a 5f 88 13 05 08 11 04 84 95 13 06 08 11 04 84 08 11 05 84 95 9e 08 11 05 84 11 06}  //weight: 10, accuracy: Low
        $x_10_2 = {9e 09 11 08 03 11 08 91 08 08 11 04 84 95 08 11 05 84 95 d7 6e 20 [0-4] 6a 5f 84 95 61 86 9c 11 08 17 d6 13 08 00 11 08 11 07 fe 02 13 0c 11 0c 2c 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_GJ_2147777586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.GJ!MTB"
        threat_id = "2147777586"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 05 11 05 28 [0-4] 13 06 11 06 72 [0-21] 13 07 11 07 14 18 8d [0-4] 13 08 11 08 16 28 [0-9] 16 9a 28 [0-4] a2 11 08 17 11 04 a2 11 08 6f}  //weight: 10, accuracy: Low
        $x_2_2 = "GetMethod" ascii //weight: 2
        $x_2_3 = "Invoke" ascii //weight: 2
        $x_2_4 = "TransformFinalBlock" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_YL_2147777587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.YL!MTB"
        threat_id = "2147777587"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 11 07 07 11 07 18 5a 18 6f [0-4] 1f 10 28 [0-4] 9c 00 11 07 17 58 13 07 11 07 08 fe 04 13 08 11 08 2d d7}  //weight: 10, accuracy: Low
        $x_2_2 = "Invoke" ascii //weight: 2
        $x_2_3 = "GetMethod" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_AAU_2147777920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.AAU!MTB"
        threat_id = "2147777920"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {9a 0c 08 19 8d [0-4] 25 16 7e [0-4] a2 25 17 7e [0-4] a2 25 18 72 [0-4] a2 28 [0-4] 26 20 00 08 00 00 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "FallbackBuffer" ascii //weight: 2
        $x_2_3 = "WSTRBufferMarshaler" ascii //weight: 2
        $x_2_4 = "InvokeMember" ascii //weight: 2
        $x_2_5 = "CreateInstance" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_AAV_2147778085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.AAV!MTB"
        threat_id = "2147778085"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {19 8d 0d 00 00 01 25 16 7e [0-2] 00 00 04 a2 25 17 7e [0-2] 00 00 04 a2 25 18 72 [0-3] 70 a2}  //weight: 10, accuracy: Low
        $x_2_2 = "FromBase64String" ascii //weight: 2
        $x_2_3 = "StrReverse" ascii //weight: 2
        $x_2_4 = "CreateInstance" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_AAX_2147778086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.AAX!MTB"
        threat_id = "2147778086"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {9a 0c 08 19 8d [0-4] 25 16 7e [0-4] a2 25 17 7e [0-4] a2 25 18 72 [0-4] a2 28 [0-4] 26 20 00 08 00 00 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "FallbackBuffer" ascii //weight: 2
        $x_2_3 = "WSTRBufferMarshaler" ascii //weight: 2
        $x_2_4 = "Activator" ascii //weight: 2
        $x_2_5 = "CreateInstance" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_AAX_2147778086_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.AAX!MTB"
        threat_id = "2147778086"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 07 1f 21 8c [0-4] 16 28 [0-4] 07 1f 7e 8c [0-4] 16 28 [0-15] 13 06 11 06 2c 3d 06 1f 21 8c [0-4] 07 1f 0e 8c [0-9] 1f 5e 8c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0a 2b 17 06 07 28}  //weight: 10, accuracy: Low
        $x_2_2 = "CreateInstance" ascii //weight: 2
        $x_2_3 = "Activator" ascii //weight: 2
        $x_2_4 = "ForNextCheckObj" ascii //weight: 2
        $x_2_5 = "FromBase64String" ascii //weight: 2
        $x_2_6 = "StrReverse" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_ABK_2147778087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.ABK!MTB"
        threat_id = "2147778087"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 11 09 07 11 09 18 5a 18 6f [0-4] 1f 10 28 [0-4] d2 9c 00 11 09 17 58 13 09 11 09 08 fe 04 13 0a 11 0a 2d d6}  //weight: 10, accuracy: Low
        $x_2_2 = "LateBinding" ascii //weight: 2
        $x_2_3 = "GetMethod" ascii //weight: 2
        $x_2_4 = "Invoke" ascii //weight: 2
        $x_2_5 = "GetAssemblies" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_ABY_2147778088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.ABY!MTB"
        threat_id = "2147778088"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 11 09 07 11 09 18 5a 18 [0-5] 1f 10 [0-5] d2 9c}  //weight: 10, accuracy: Low
        $x_2_2 = "AutoScaleBaseSize" ascii //weight: 2
        $x_2_3 = "Substring" ascii //weight: 2
        $x_2_4 = "ToInt32" ascii //weight: 2
        $x_2_5 = "Replace" ascii //weight: 2
        $x_2_6 = "Invoke" ascii //weight: 2
        $x_2_7 = "LateBinding" ascii //weight: 2
        $x_2_8 = "GetType" ascii //weight: 2
        $x_2_9 = "GetAssemblies" ascii //weight: 2
        $x_2_10 = "GetMethod" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Kryptik_ABX_2147778089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.ABX!MTB"
        threat_id = "2147778089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 16 03 a2 6f [0-9] 0b 07 6f [0-4] 1f 09 9a 0c 14 d0 [0-15] 18 8d [0-4] 25 16 08 a2 25 17 19 8d [0-4] 25 16 7e [0-4] a2 25 17}  //weight: 10, accuracy: Low
        $x_10_2 = {a2 25 18 72 [0-4] a2 a2 25 0d 14 14 18 8d [0-4] 25 16 17 9c 25 13 04 17 28 [0-4] 26 11 04 16 91 2d 02 2b 09 09 16 9a 28}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_YJ_2147778850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.YJ!MTB"
        threat_id = "2147778850"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {04 08 04 6f ?? ?? ?? ?? 5d 17 d6 28 ?? ?? ?? ?? da 0d 06 09 28 [0-15] 0a 00 08 17 d6 0c 08 11 04 13 05 11 05 31 c7}  //weight: 10, accuracy: Low
        $x_10_2 = {04 08 04 6f ?? ?? ?? ?? 5d 17 d6 28 ?? ?? ?? ?? da 0d 18 2b be 06 09 28 [0-15] 0a 19 2b a9 08 17 d6 0c 08 11 04 13 05 11 05 31 c2}  //weight: 10, accuracy: Low
        $x_2_3 = "FromBase64String" ascii //weight: 2
        $x_2_4 = "StrReverse" ascii //weight: 2
        $x_2_5 = "LateBinding" ascii //weight: 2
        $x_2_6 = "CallByName" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Kryptik_XL_2147778865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.XL!MTB"
        threat_id = "2147778865"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 05 11 04 6f [0-4] 0d 06 09 28 [0-4] 08 da 28 [0-4] 28 [0-4] 28 [0-4] 0a 11 04 17 d6 13 04 00 11 04 11 06 fe 04 13 07 11 07 2d ca}  //weight: 10, accuracy: Low
        $x_2_2 = "EntryPoint" ascii //weight: 2
        $x_2_3 = "FromBase64" ascii //weight: 2
        $x_2_4 = "Invoke" ascii //weight: 2
        $x_2_5 = "Assembly" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_ABDIND_2147805128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.ABDIND!MTB"
        threat_id = "2147805128"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$90c8961f-6a23-4f05-b273-35f50f7554d7" ascii //weight: 10
        $x_1_2 = "Buffer" ascii //weight: 1
        $x_1_3 = "Convo" ascii //weight: 1
        $x_1_4 = "ToString" ascii //weight: 1
        $x_1_5 = "Worker2" ascii //weight: 1
        $x_1_6 = "Jmekelwuwzudyywsibkp" ascii //weight: 1
        $x_1_7 = "Worker1" ascii //weight: 1
        $x_1_8 = "IsEverythingDone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_ABDINDAI_2147805646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.ABDINDAI!MTB"
        threat_id = "2147805646"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$2486866f-5d72-4fdd-a8bf-8e15659c4f01" ascii //weight: 10
        $x_1_2 = "SortComparator" ascii //weight: 1
        $x_1_3 = "SetComparator" ascii //weight: 1
        $x_1_4 = "ResolveImporter" ascii //weight: 1
        $x_1_5 = "CountImporter" ascii //weight: 1
        $x_1_6 = "PushImporter" ascii //weight: 1
        $x_1_7 = "FindImporter" ascii //weight: 1
        $x_1_8 = "InstantiateImporter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_ZKNISA_2147805648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.ZKNISA!MTB"
        threat_id = "2147805648"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$a7a8527c-37ae-443b-8daa-61001cbd2658" ascii //weight: 10
        $x_1_2 = "AddCBS_Values" ascii //weight: 1
        $x_1_3 = "FLuxCenter" ascii //weight: 1
        $x_1_4 = "PlaySound" ascii //weight: 1
        $x_1_5 = "ObjectIdentifier" ascii //weight: 1
        $x_1_6 = "PlayASound" ascii //weight: 1
        $x_1_7 = "CheckForCollision" ascii //weight: 1
        $x_1_8 = "checkWinner" ascii //weight: 1
        $x_1_9 = "HitsPaddle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_ASMS_2147805649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.ASMS!MTB"
        threat_id = "2147805649"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$b50d3fc9-dd48-48ed-a31f-d17a39344028" ascii //weight: 10
        $x_1_2 = "AddCBS_Values" ascii //weight: 1
        $x_1_3 = "FLuxCenter" ascii //weight: 1
        $x_1_4 = "BSTRMarshaler" ascii //weight: 1
        $x_1_5 = "ObjectIdentifier" ascii //weight: 1
        $x_1_6 = "createSquares" ascii //weight: 1
        $x_1_7 = "newGameButton_Click" ascii //weight: 1
        $x_1_8 = "updateBoard" ascii //weight: 1
        $x_1_9 = "TetrisGame_KeyDown" ascii //weight: 1
        $x_1_10 = "TetrisGame_KeyPress" ascii //weight: 1
        $x_1_11 = "TetrisGame_KeyUp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_GILU_2147805867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.GILU!MTB"
        threat_id = "2147805867"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$b50d3fc9-dd48-48ed-a31f-d17a39344028" ascii //weight: 10
        $x_1_2 = "AddCBS_Values" ascii //weight: 1
        $x_1_3 = "FLuxCenter" ascii //weight: 1
        $x_1_4 = "BSTRMarshaler" ascii //weight: 1
        $x_1_5 = "ObjectIdentifier" ascii //weight: 1
        $x_1_6 = "createSquares" ascii //weight: 1
        $x_1_7 = "newGameButton_Click" ascii //weight: 1
        $x_1_8 = "squaresKey" ascii //weight: 1
        $x_1_9 = "updateBoard" ascii //weight: 1
        $x_1_10 = "ObjectHolderListGame_KeyDown" ascii //weight: 1
        $x_1_11 = "ObjectHolderListGame_KeyPress" ascii //weight: 1
        $x_1_12 = "ObjectHolderListGame_KeyUp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_NURA_2147805872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.NURA!MTB"
        threat_id = "2147805872"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$1A70F520-6373-45D1-BE53-E8C3D67DF5A7" ascii //weight: 10
        $x_1_2 = "BSTRMarshaler" ascii //weight: 1
        $x_1_3 = "FLuxCenter" ascii //weight: 1
        $x_1_4 = "ObjectIdentifier" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_TINK_2147806226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.TINK!MTB"
        threat_id = "2147806226"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$e0ecc6e0-76a7-4415-9c5a-5931447b99c9" ascii //weight: 10
        $x_1_2 = "CF001231" ascii //weight: 1
        $x_1_3 = "CF234052" ascii //weight: 1
        $x_1_4 = "CF32148123" ascii //weight: 1
        $x_1_5 = "CF3424235665" ascii //weight: 1
        $x_1_6 = "validateLogin" ascii //weight: 1
        $x_1_7 = "isGuest" ascii //weight: 1
        $x_1_8 = "createTokenAuth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_FINKT_2147806228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.FINKT!MTB"
        threat_id = "2147806228"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$a39e2ae0-dbfe-45fc-8953-d2f7778ce248" ascii //weight: 10
        $x_1_2 = "CF001231" ascii //weight: 1
        $x_1_3 = "CF234052" ascii //weight: 1
        $x_1_4 = "CF32148123" ascii //weight: 1
        $x_1_5 = "CF3424235665" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_GINKT_2147806229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.GINKT!MTB"
        threat_id = "2147806229"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$ae72b6b0-eae6-4c06-a212-e79eeccda8cd" ascii //weight: 10
        $x_1_2 = "Dispose" ascii //weight: 1
        $x_1_3 = "Q_I3" ascii //weight: 1
        $x_1_4 = {00 52 41 57 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_ITAK_2147806230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.ITAK!MTB"
        threat_id = "2147806230"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BefKoning" ascii //weight: 1
        $x_1_2 = "GasJews" ascii //weight: 1
        $x_1_3 = "GetTheJews" ascii //weight: 1
        $x_1_4 = "StartHumanExperiment" ascii //weight: 1
        $x_1_5 = "StartHumanExperimentDoubleDown" ascii //weight: 1
        $x_1_6 = "StartNurnbergProcess" ascii //weight: 1
        $x_1_7 = "SFcekNaiAtBNQNeODXGoy" ascii //weight: 1
        $x_1_8 = "IJOJbyMTtuEXtAuiIyU" ascii //weight: 1
        $x_1_9 = "bMwPaBFqboRMuRoNcc" ascii //weight: 1
        $x_1_10 = "iQTidfqtIwNCeiqKNVAyqZn" ascii //weight: 1
        $x_1_11 = "iwzxAnnEobCIXdhkQ" ascii //weight: 1
        $x_1_12 = "oHgIBAzHATBDdDtD" ascii //weight: 1
        $x_1_13 = "xNswzOIepdAFUCjGEJDnKS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_KTAB_2147806231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.KTAB!MTB"
        threat_id = "2147806231"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LepelLeeg" ascii //weight: 2
        $x_2_2 = "RemoveDatShit" ascii //weight: 2
        $x_3_3 = "Verkleperij" ascii //weight: 3
        $x_2_4 = {00 50 61 79 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_NAMTIH_2147806232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.NAMTIH!MTB"
        threat_id = "2147806232"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "fetishFoot" ascii //weight: 2
        $x_2_2 = "gpleeff" ascii //weight: 2
        $x_3_3 = "LUmioerrsdf" ascii //weight: 3
        $x_2_4 = {00 46 75 6b 61 6e 74 75 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_ZKA_2147807213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.ZKA!MTB"
        threat_id = "2147807213"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 43 00 00 70 28 ?? ?? ?? 06 0a 72 85 00 00 70 28 ?? ?? ?? 06 0b 06 72 c7 00 00 70 72 09 01 00 70 28 ?? ?? ?? 06 0a 07 72 c7 00 00 70 72 09 01 00 70 28 ?? ?? ?? 06 0b 06}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_GTSK_2147807216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.GTSK!MTB"
        threat_id = "2147807216"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 13 00 00 0a 0a 73 14 00 00 0a 0b 73 15 00 00 0a 0c 08 06 08 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f 18 00 00 0a 08 06 08 6f ?? ?? ?? 0a 1e 5b 6f 17 00 00 0a 6f ?? ?? ?? 0a 07 08 6f ?? ?? ?? 0a 17 73 1c 00 00 0a 0d 09 02 16 02 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 13 04 de 11 26 16 28 20 00 00 0a 16 8d 1b 00 00 01 13 04 de 00 11 04 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_JTSK_2147807217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.JTSK!MTB"
        threat_id = "2147807217"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 43 00 00 70 28 ?? ?? ?? 06 0a 72 85 00 00 70 28 ?? ?? ?? 06 0b 06 72 c7 00 00 70 72 29 01 00 70 28 ?? ?? ?? 06 0a 07 72 c7 00 00 70 72 29 01 00 70 28 ?? ?? ?? 06 0b 06 28 ?? ?? ?? 0a 0c 08 72 6b 01 00 70 6f ?? ?? ?? 0a 0d 09 72 8d 01 00 70 6f ?? ?? ?? 0a 13 04 11 04 14 1a 8d 01 00 00 01 13 07 11 07 16 28 03 00 00 0a 6f ?? ?? ?? 0a a2 11 07 17 72 99 01 00 70 a2 11 07 18 07 a2 11 07 19 16 8c 0a 00 00 01 a2 11 07 6f ?? ?? ?? 0a 26 17 13 06 de 13 13 05 11 05 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 16 13 06 de 00 11 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_KSRS_2147807218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.KSRS!MTB"
        threat_id = "2147807218"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 26 0a 20 83 00 00 00 28 ?? ?? ?? 06 25 26 28 ?? ?? ?? 06 25 26 0b 06 20 c4 00 00 00 28 ?? ?? ?? 06 25 26 20 05 01 00 00 28 ?? ?? ?? 06 25 26 28 ?? ?? ?? 06 25 26 0a 07 20 c4 00 00 00 28 ?? ?? ?? 06 25 26 20 05 01 00 00 28 ?? ?? ?? 06 25 26 28 ?? ?? ?? 06 25 26 0b 06 28 ?? ?? ?? 0a 25 26 0c 08 20 26 01 00 00 28 ?? ?? ?? 06 25 26 6f ?? ?? ?? 0a 25 26 0d 09 20 47 01 00 00 28 ?? ?? ?? 06 25 26 6f ?? ?? ?? 0a 25 26 13 04 11 04 14 1a 28 ?? ?? ?? 06 25 26 13 07 11 07 16 28 ?? ?? ?? 0a 25 26 6f ?? ?? ?? 0a 25 26 a2 11 07 17 72 5b 00 00 70 a2 11 07 18 07 a2 11 07 19 16 8c 06 00 00 01 a2 11 07 6f ?? ?? ?? 0a 25 26 26 28 ?? ?? ?? 06 28 ?? ?? ?? 06 17 13 06 de 15 13 05 11 05 6f ?? ?? ?? 0a 25 26 28 ?? ?? ?? 0a 16 13 06 de 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_TCKA_2147807219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.TCKA!MTB"
        threat_id = "2147807219"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 4d 00 00 70 28 ?? ?? ?? 06 0a 72 8f 00 00 70 28 ?? ?? ?? 06 0b 06 72 d1 00 00 70 72 13 01 00 70 28 ?? ?? ?? 06 0a 07 72 d1 00 00 70 72 13 01 00 70 28 ?? ?? ?? 06 0b 06 28 ?? ?? ?? 0a 0c 08 72 35 01 00 70 6f ?? ?? ?? 0a 0d 09 72 57 01 00 70 6f ?? ?? ?? 0a 13 04 11 04 14 1a 8d 01 00 00 01 13 07 11 07 16 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a a2 11 07 17 72 5f 01 00 70 a2 11 07 18 07 a2 11 07 19 16 8c 0d 00 00 01 a2 11 07 6f ?? ?? ?? 0a 26 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 17 13 06 de 13 13 05 11 05 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 16 13 06 de 00 11 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_YAUD_2147807531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.YAUD!MTB"
        threat_id = "2147807531"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DA43FE0D-B4A1-4F48-AD15-1B9EE3FABF94" ascii //weight: 10
        $x_1_2 = "EX00001" ascii //weight: 1
        $x_1_3 = "EX00002" ascii //weight: 1
        $x_1_4 = "EX00003" ascii //weight: 1
        $x_1_5 = "EX00006" ascii //weight: 1
        $x_1_6 = "GetPixel" ascii //weight: 1
        $x_1_7 = "ToWin32" ascii //weight: 1
        $x_1_8 = {00 4c 65 76 65 6c 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 78 73 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Kryptik_AUSE_2147807532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.AUSE!MTB"
        threat_id = "2147807532"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 4c 00 00 0a 0c 73 4d 00 00 0a 0a 08 06 28 ?? ?? ?? 0a 72 eb 2e 00 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 18 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 0d 02 13 04 09 11 04 16 11 04 8e b7 6f ?? ?? ?? 0a 0b de 0f 25 28 ?? ?? ?? 0a 13 05 28 ?? ?? ?? 0a de 00 07 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_MC_2147807762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.MC!MTB"
        threat_id = "2147807762"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "142f9043-1b98-47d3-b750-e6c43fadb2f5" ascii //weight: 1
        $x_1_2 = "OrderQueue" wide //weight: 1
        $x_1_3 = "Phmqfiqcmdkd" wide //weight: 1
        $x_1_4 = "Rhqeracbiv" wide //weight: 1
        $x_1_5 = "powershell" wide //weight: 1
        $x_1_6 = "Test-Connection www.twitter.com" wide //weight: 1
        $x_1_7 = "Sleep" ascii //weight: 1
        $x_1_8 = "Invoke" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "Replace" ascii //weight: 1
        $x_1_11 = "GetString" ascii //weight: 1
        $x_1_12 = "set_CreateNoWindow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_GMBH_2147807922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.GMBH!MTB"
        threat_id = "2147807922"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 13 00 00 0a 0b 73 14 00 00 0a 0c 08 06 08 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 06 08 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 08 6f ?? ?? ?? 0a 17 73 1b 00 00 0a 0d 09 02 16 02 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 13 04 de 11 26 16 28 ?? ?? ?? 0a 16 8d 1b 00 00 01 13 04 de 00 11 04 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_BSDJ_2147808412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.BSDJ!MTB"
        threat_id = "2147808412"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FukaBumpa" ascii //weight: 2
        $x_2_2 = "IsCalculated" ascii //weight: 2
        $x_3_3 = "ZwamWorts" ascii //weight: 3
        $x_2_4 = {00 48 69 74 6c 65 72 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_HSZL_2147808413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.HSZL!MTB"
        threat_id = "2147808413"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 1c 00 00 0a 0a 73 1d 00 00 0a 0b 73 1e 00 00 0a 0c 08 06 08 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 06 08 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 08 6f ?? ?? ?? 0a 17 73 25 00 00 0a 0d 09 02 16 02 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 13 04 de 11 26 16 28 29 00 00 0a 16 8d 22 00 00 01 13 04 de 00 11 04 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_ESR_2147808416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.ESR!MTB"
        threat_id = "2147808416"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d0 5a 00 00 01 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 17 8d 17 00 00 01 25 16 d0 01 00 00 1b 28 ?? ?? ?? 0a a2 28 ?? ?? ?? 0a 04 17 8d 10 00 00 01 25 16 02 a2 6f ?? ?? ?? 0a 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_ME_2147808840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.ME!MTB"
        threat_id = "2147808840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 73 16 00 00 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 06 1f 64 73 ?? ?? ?? 0a 1f 10 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 72 ?? ?? 00 70 28 ?? ?? ?? 06 28 ?? ?? ?? 06 17 73 ?? ?? ?? 0a 13 01 20 00 00 00 00 28 ?? ?? ?? 06 39 ?? 00 00 00 26 20 00 00 00 00 38}  //weight: 1, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "InitComposer" ascii //weight: 1
        $x_1_5 = "AwakeComposer" ascii //weight: 1
        $x_1_6 = "InvokeComposer" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "CreateEncryptor" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_11 = "set_Key" ascii //weight: 1
        $x_1_12 = "set_IV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_MF_2147808841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.MF!MTB"
        threat_id = "2147808841"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4cde55fd-a6de-428f-ad58-4a836d9e6571" ascii //weight: 1
        $x_1_2 = "cce9dd71b9f241af94912880ae9430ed" ascii //weight: 1
        $x_1_3 = "NOKIA PRO" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "ContainsKey" ascii //weight: 1
        $x_1_6 = "NextBytes" ascii //weight: 1
        $x_1_7 = "GetString" ascii //weight: 1
        $x_1_8 = "Replace" ascii //weight: 1
        $x_1_9 = "MemoryStream" ascii //weight: 1
        $x_1_10 = "Write" ascii //weight: 1
        $x_1_11 = "GetData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_TSR_2147809030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.TSR!MTB"
        threat_id = "2147809030"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d0 51 00 00 01 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 17 8d 17 00 00 01 25 16 d0 01 00 00 1b 28 ?? ?? ?? 0a a2 28 ?? ?? ?? 0a 04 17 8d 10 00 00 01 25 16 02 a2 6f ?? ?? ?? 0a 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_LTAB_2147809041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.LTAB!MTB"
        threat_id = "2147809041"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 1a 00 00 0a 0a 73 1b 00 00 0a 0b 73 1c 00 00 0a 0c 08 06 08 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 06 08 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 08 6f ?? ?? ?? 0a 17 73 23 00 00 0a 0d 09 02 16 02 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 13 04 de 11}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_PALLV_2147809042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.PALLV!MTB"
        threat_id = "2147809042"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 02 26 16 02 6f ?? ?? ?? 0a d4 8d 25 00 00 01 0a 02 06 16 06 8e 69 6f ?? ?? ?? 0a 26 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_PSA_2147831469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.PSA!MTB"
        threat_id = "2147831469"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 55 a2 0b 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 68 00 00 00 70 07 00 00 76 00 00 00 87 37 00 00 91 00 00 00 b8}  //weight: 5, accuracy: High
        $x_1_2 = "DebuggingModes" ascii //weight: 1
        $x_1_3 = "System.Security.Cryptography.CAPI+CRYPT_ALGORITHM_IDENTIFIER2" ascii //weight: 1
        $x_1_4 = "GetProcessById" ascii //weight: 1
        $x_1_5 = "WriteLine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_SAMD_2147896139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.SAMD!MTB"
        threat_id = "2147896139"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "62"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CreateDecryptor" ascii //weight: 10
        $x_10_2 = "GetBytes" ascii //weight: 10
        $x_10_3 = "GetMethod" ascii //weight: 10
        $x_10_4 = "GetType" ascii //weight: 10
        $x_10_5 = {00 50 61 79 00}  //weight: 10, accuracy: High
        $x_10_6 = "Invoke" ascii //weight: 10
        $x_1_7 = "FUCKMusr" ascii //weight: 1
        $x_1_8 = "VoorFoef" ascii //weight: 1
        $x_1_9 = "DeemBal" ascii //weight: 1
        $x_1_10 = "Musr" ascii //weight: 1
        $x_1_11 = "Gekkk" ascii //weight: 1
        $x_1_12 = "Se5fs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Kryptik_NBL_2147896413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.NBL!MTB"
        threat_id = "2147896413"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 06 11 04 11 07 11 07 08 91 11 07 09 91 58 20 ff 00 00 00 5f 91 06 11 04 91 61 9c 20 14 00 00 00 38 e1 fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {fe 0c 05 00 fe 0c 05 00 5a 6e fe 0c 1d 00 5e 6d fe 0e 05 00 fe 0c 0d 00 fe 0c 0d 00 18 62 61 fe 0e 0d 00 fe 0c 0d 00 fe 0c 34 00 58 fe 0e 0d 00 fe 0c 0d 00 fe 0c 0d 00 1d 64 61 fe 0e 0d 00 fe 0c 0d 00 fe 0c 27 00 58 fe 0e 0d 00 fe 0c 0d 00 fe 0c 0d 00 1f 09 62 61 fe 0e 0d 00 fe 0c 0d 00 fe 0c 05 00 58 fe 0e 0d 00 fe 0c 2f 00 1f 12 62 fe 0c 2f 00 58 fe 0c 34 00 61 fe 0c 0d 00 58 fe 0e 0d 00 fe 0c 0d 00 76 6c 6d 58 13 11 20 15 01 00 00 38 12 d4 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_PGK_2147939522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.PGK!MTB"
        threat_id = "2147939522"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 33 00 00 70 72 35 00 00 70 17 8d ?? 00 00 01 25 16 1f 25 9d 28 ?? 00 00 0a 7e ?? 00 00 04 25 2d 17}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_PGKR_2147939660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.PGKR!MTB"
        threat_id = "2147939660"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d0 02 00 00 02 28 ?? 00 00 0a 6f ?? 00 00 0a 72 01 00 00 70 72 07 00 00 70 6f ?? 00 00 0a 28 ?? 00 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kryptik_PGT_2147940190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptik.PGT!MTB"
        threat_id = "2147940190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {94 58 20 00 01 00 00 5d 94 fe 0e 0e 00 fe 0c 07 00 fe 0c 0c 00 fe 09 00 00 fe 0c 0c 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

