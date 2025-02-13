rule VirTool_MSIL_Obfuscator_A_2147644047_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.A"
        threat_id = "2147644047"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 65 74 5f 4e 65 74 77 6f 72 6b 00 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 00 53 6c 65 65 70 00 44 65 6c 65 74 65 00 42 79 74 65 00 49 6e 74 65 72 61 63 74 69 6f 6e 00 41 70 70 57 69 6e 53 74 79 6c 65 00 53 68 65 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 61 69 6e 44 69 72 00 59 6f 75 72 46 69 6c 65 00 53 65 61 72 63 68 00 70 61 74 68 4e 61 6d 65 00 53 70 72 65 61 64 00 6d 79 45 78 65 4e 61 6d 65 [0-255] 61 72 63 68 69 76 65 54 6f 49 6e 6a 65 63 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_D_2147654005_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.D"
        threat_id = "2147654005"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "get_HKCU_Loc" ascii //weight: 1
        $x_1_2 = "get_UpdatePassword" ascii //weight: 1
        $x_1_3 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 42 00 75 00 69 00 6c 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "$#%#'&(&)&*&+&,+-&.&/&" wide //weight: 1
        $x_1_5 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 [0-3] 5c 00 64 00 2b 00 2e 00 5c 00 64 00 2b 00 2e 00 5c 00 64 00 2b 00 2e 00 5c 00 64 00 2b 00 [0-2] 47 00 45 00 54 00}  //weight: 1, accuracy: Low
        $x_1_6 = {5d 00 00 25 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_E_2147657461_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.E"
        threat_id = "2147657461"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\Brendan\\Desktop\\Crypters\\Sickanders Crypter " ascii //weight: 1
        $x_1_2 = {5f 43 6f 72 45 78 65 4d 61 69 6e 00 6d 73 63 6f 72 65 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {4d 79 41 70 70 6c 69 63 61 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 79 43 6f 6d 70 75 74 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_W_2147662829_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.W"
        threat_id = "2147662829"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://bloodcrypt.com/info/info.txt" wide //weight: 1
        $x_1_2 = "Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "\\v2.0.50727\\vbc.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_X_2147662830_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.X"
        threat_id = "2147662830"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 ?? 19 4a 00 61 00 76 00 61 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_2 = "cheese" wide //weight: 1
        $x_1_3 = "shank" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_AA_2147663123_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.AA"
        threat_id = "2147663123"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 01 16 fe 01 fe 0e ?? 01 fe 0c ?? 01 2d ?? 00 14}  //weight: 1, accuracy: Low
        $x_1_2 = {02 11 05 02 11 04 17 59 91 9c 20}  //weight: 1, accuracy: High
        $x_1_3 = {02 11 06 02 11 05 17 59 91 9c 20}  //weight: 1, accuracy: High
        $x_1_4 = {02 11 07 02 11 06 17 59 91 9c 20}  //weight: 1, accuracy: High
        $x_1_5 = {04 1f 19 64 04 1d 62 60 10 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_MSIL_Obfuscator_AE_2147668125_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.AE"
        threat_id = "2147668125"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0d 16 11 0d 16 95 11 0e 16 95 61 9e 11 0d 17 11 0d 17 95 11 0e 17 95 5a 9e 11 0d 18 11 0d 18 95 11 0e 18 95 58 9e 11}  //weight: 1, accuracy: High
        $x_1_2 = {13 0d 1f 10 8d ?? 00 00 01 13 0e 16 13 ?? 2b 38 11 0d 11 ?? 11 0c 9e 11 0e 11 ?? 11 0a 9e 11 0a 18 64 11 0a 1e 62 60 13 09 11 0b 1b 64 11 0b 1f 1f 62 60 13 0a 11}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 39 11 06 25 4b 11 0d 11 ?? 1f 0f 5f 95 61 54 11 0d 11 ?? 1f 0f 5f 11 0d 11 ?? 1f 0f 5f 95 11 06 25 1a 58 13 06 4b 61 20 84 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_AJ_2147681506_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.AJ"
        threat_id = "2147681506"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Avto_Bot.exe" ascii //weight: 10
        $x_1_2 = "\\MsMpEng.exe" wide //weight: 1
        $x_1_3 = "svchost" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_AK_2147682135_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.AK"
        threat_id = "2147682135"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_CorExeMain" ascii //weight: 1
        $x_1_2 = {20 dd 5b b4 7c 20 b7 29 29 64 61 20 b2 2e fe 4e 20 6b 28 84 58 61 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_AL_2147682851_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.AL"
        threat_id = "2147682851"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 50 61 73 73 50 68 72 61 73 65 00 5f 70 61 73 73 50 68 72 61 73 65 53 74 72 65 6e 67 74 68 00 5f 53 61 6c 74 56 61 6c 75 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 00 44 6c 6c 49 6d 70 6f 72 74 41 74 74 72 69 62 75 74 65 00 [0-32] 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_3 = "The salt value used to foil hackers attempting to crack the encryption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_AN_2147685935_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.AN"
        threat_id = "2147685935"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 53 74 75 62 31 2e 4d 79 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 53 74 50 4f 26 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 44 74 75 62 2e 4d 79 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 55 53 47 5f 53 54 55 42 2e 4d 79 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 59 61 6e 6f 41 74 74 72 69 62 75 74 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 6e 63 4f 71 62 57 75 64 4a 48 32 45 4c 55 58 58 76 36 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 73 74 75 62 32 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 73 74 75 62 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_100_9 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Obfuscator_AO_2147686683_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.AO"
        threat_id = "2147686683"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mr.Hackers DZ DEV-POINT.snk" ascii //weight: 1
        $x_1_2 = "Hamza.resources" ascii //weight: 1
        $x_1_3 = "%ProcessName%" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_AP_2147687140_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.AP"
        threat_id = "2147687140"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 17 58 13 06 11 06 11 05 8e 69 32 cb 11 04 17 58 13 04 11 04 09 8e 69 32 ac 14 2a 08 2a}  //weight: 1, accuracy: High
        $x_1_2 = {03 06 03 8e 69 5d 91 06 04 58 03 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 81 ?? ?? ?? ?? 06 17 58 0a 06 02 8e 69 32 c9 02 2a}  //weight: 1, accuracy: Low
        $x_1_3 = {1f 7f 5f 19 2e 1d 11 ?? 1d 64 20 ff ff 01 00 5f 13 ?? 11 ?? 18 64 1f 1f 5f 18 58 13 ?? ?? 19 58 ?? 2b 19}  //weight: 1, accuracy: Low
        $x_1_4 = {17 5f 2d 1d 11 (07|08) 20 ff ff 00 00 5f 1c 64 13 (0b|0c) 11 (07|08) 18 64 1f 0f 5f 19 58 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_AS_2147694878_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.AS"
        threat_id = "2147694878"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PqpKQQbSGFalsePqpKQQbSGPqpKQQbSGFalsePqpKQQbSG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_AT_2147695055_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.AT"
        threat_id = "2147695055"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 0c 06 16 07 6f ?? ?? ?? ?? 08 20 ff ff 00 00 5f d1 8c ?? ?? ?? ?? 06 07 17 58 6f ?? ?? ?? ?? 28 ?? ?? ?? ?? 0a 07 17 58}  //weight: 1, accuracy: Low
        $x_1_2 = {20 b7 00 00 00 59 0c 08 1f 27 61 0c 08 20 d7 00 00 00 58 0c 08 07 59 0c 08 20 dd 00 00 00 59 0c 08 66 0c 08 20 a4 00 00 00 61 0c 08 07 61}  //weight: 1, accuracy: High
        $x_1_3 = {0c 08 17 58 0c 08 07 58 0c 08 20 ?? ?? ?? ?? 58 0c 08 07 61 0c 08 07 59 0c 08 17 59 0c 06 16 07 6f ?? ?? ?? ?? 08 20 ff ff 00 00 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_MSIL_Obfuscator_AU_2147695061_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.AU"
        threat_id = "2147695061"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 02 11 01 11 03 28 ?? 00 00 06 26 [0-32] 11 01 11 03 28 ?? 00 00 06 11 00 11 04 11 01 29 01 00 00 11 26}  //weight: 1, accuracy: Low
        $x_1_2 = {11 02 11 01 11 03 28 ?? 00 00 06 26 20 [0-16] 11 00 11 04 11 01 29 01 00 00 11 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_MSIL_Obfuscator_Devpoint_2147695401_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.Devpoint"
        threat_id = "2147695401"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mr.Hackers DZ DEV-POINT.snk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_AX_2147695531_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.AX"
        threat_id = "2147695531"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0e 18 00 fe 0c 1c 00 fe 0c 1b 00 fe 0c 1a 00 fe 0c 19 00 28}  //weight: 1, accuracy: High
        $x_1_2 = {fe 0e 0b 00 fe 0c 0f 00 fe 0c 0e 00 fe 0c 0d 00 fe 0c 0c 00 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_MSIL_Obfuscator_AY_2147695532_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.AY"
        threat_id = "2147695532"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 00 34 00 ?? ?? 38 00 36 00 ?? ?? 31 00 31 00 33 00 ?? ?? 38 00 31 00 ?? ?? 36 00 35 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BC_2147695733_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BC"
        threat_id = "2147695733"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 11 05 02 11 05 91 06 61 07 09 91 61 b4 9c 09 03 6f ?? ?? ?? ?? 17 da}  //weight: 1, accuracy: Low
        $x_1_2 = {08 11 04 02 11 04 91 07 61 06 09 91 61 28 ?? ?? ?? ?? 9c 09 03 6f ?? ?? ?? ?? 17 59}  //weight: 1, accuracy: Low
        $x_1_3 = {0b 02 02 8e b7 17 da 91 1f ?? 61 0a 02 8e b7 17 d6}  //weight: 1, accuracy: Low
        $x_1_4 = {0a 02 02 8e 69 17 59 91 1f ?? 61 28 ?? ?? ?? ?? 0b 02 8e 69 17 58}  //weight: 1, accuracy: Low
        $x_1_5 = {0a 02 02 8e 69 17 59 91 1f 70 61 0b 02 8e 69 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_MSIL_Obfuscator_BD_2147695734_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BD"
        threat_id = "2147695734"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 09 03 09 91 04 09 04 8e b7 5d 91 61 08 09 08 8e b7 5d 91 61 9c 00 09 17 d6 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BE_2147695737_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BE"
        threat_id = "2147695737"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "erRXb0XPkjhYPePrEP6GLacUFFH65OlJBppLgqTxMi0w2QgFk4OKfSOwBwuxtEG1BlPdSMd0GJxTCrGfL4f2Y4pvZijNhf3AgCgFc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BF_2147695738_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BF"
        threat_id = "2147695738"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 02 06 91 03 07 91 61 d2 9c 07 17 58 0b 07 03 8e 69 32}  //weight: 1, accuracy: High
        $x_1_2 = {0c 1a 07 6f ?? ?? ?? ?? 5a 07 6f ?? ?? ?? ?? 5a 8d}  //weight: 1, accuracy: Low
        $x_1_3 = "PixelFormat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BF_2147695738_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BF"
        threat_id = "2147695738"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {02 06 02 06 91 03 07 91 61 d2 9c 07 17 58 0b 07 03 8e 69 32}  //weight: 100, accuracy: High
        $x_1_2 = {2e 72 65 73 6f 75 72 63 65 73 00 [0-12] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 72 65 73 6f 75 72 63 65 73 00 [0-12] 45 00 [0-6] 45 00 [0-6] 45 00 [0-6] 45 00 [0-6] 45 00 [0-6] 45 00 [0-6] 45 00 [0-6] 45}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 72 65 73 6f 75 72 63 65 73 00 [0-12] 46 00 [0-6] 46 00 [0-6] 46 00 [0-6] 46 00 [0-6] 46 00 [0-6] 46 00 [0-6] 46 00 [0-6] 46}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 72 65 73 6f 75 72 63 65 73 00 [0-12] 51 00 [0-6] 51 00 [0-6] 51 00 [0-6] 51 00 [0-6] 51 00 [0-6] 51 00 [0-6] 51 00 [0-6] 51}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 72 65 73 6f 75 72 63 65 73 00 [0-12] 50 00 [0-6] 50 00 [0-6] 50 00 [0-6] 50 00 [0-6] 50 00 [0-6] 50 00 [0-6] 50 00 [0-6] 50}  //weight: 1, accuracy: Low
        $x_1_7 = {2e 72 65 73 6f 75 72 63 65 73 00 [0-12] 59 00 [0-6] 59 00 [0-6] 59 00 [0-6] 59 00 [0-6] 59 00 [0-6] 59 00 [0-6] 59 00 [0-6] 59}  //weight: 1, accuracy: Low
        $x_1_8 = {2e 72 65 73 6f 75 72 63 65 73 00 [0-12] 5a 00 [0-6] 5a 00 [0-6] 5a 00 [0-6] 5a 00 [0-6] 5a 00 [0-6] 5a 00 [0-6] 5a 00 [0-6] 5a}  //weight: 1, accuracy: Low
        $x_1_9 = {2e 72 65 73 6f 75 72 63 65 73 00 [0-12] 63 00 [0-6] 63 00 [0-6] 63 00 [0-6] 63 00 [0-6] 63 00 [0-6] 63 00 [0-6] 63 00 [0-6] 63}  //weight: 1, accuracy: Low
        $x_1_10 = {53 79 73 74 65 6d 00 4f 62 6a 65 63 74 00 61 [0-3] 61 [0-3] 61 [0-3] 61 [0-3] 61 [0-3] 61 [0-3] 61 [0-3] 61}  //weight: 1, accuracy: Low
        $x_1_11 = {30 00 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23}  //weight: 1, accuracy: Low
        $x_1_12 = {31 00 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23}  //weight: 1, accuracy: Low
        $x_1_13 = {32 00 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23}  //weight: 1, accuracy: Low
        $x_1_14 = {33 00 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23}  //weight: 1, accuracy: Low
        $x_1_15 = {34 00 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23}  //weight: 1, accuracy: Low
        $x_1_16 = {35 00 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23}  //weight: 1, accuracy: Low
        $x_1_17 = {36 00 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23}  //weight: 1, accuracy: Low
        $x_1_18 = {37 00 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23}  //weight: 1, accuracy: Low
        $x_1_19 = {38 00 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23}  //weight: 1, accuracy: Low
        $x_1_20 = {39 00 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23 00 [0-6] 23}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Obfuscator_BG_2147696185_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BG"
        threat_id = "2147696185"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 03 09 18 6f ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 04 07 6f ?? ?? ?? ?? 28 ?? ?? ?? ?? 6a 61 b7 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 04 06 11 04 6f ?? ?? ?? ?? 26 07 04 6f ?? ?? ?? ?? 17 da}  //weight: 10, accuracy: Low
        $x_1_2 = "Windows 2013(TM)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BH_2147696223_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BH"
        threat_id = "2147696223"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e b7 5d 13 ?? 11 ?? 11 ?? 91 11 ?? 11 ?? 91 61 13 ?? 11 ?? 17 d6 13 ?? 11 ?? 11}  //weight: 1, accuracy: Low
        $x_1_2 = {8e b7 5d 13 ?? 11 ?? 13 ?? 11 ?? 11 ?? 91 13 ?? 11 ?? 11 ?? da 20 00 01 00 00 d6 13 ?? 11 ?? 20 00 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BI_2147696248_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BI"
        threat_id = "2147696248"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5f d8 06 1e 63 d6 0a 08 1d d6 07 20 ff 00 00 00 5f d8 07 1e 63 d6 0b 06 1e 62 07 d6 20 ff 00 00 00 5f 0c 11 04 11 06 02 11 06 91 08 b4 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BA_2147696471_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BA"
        threat_id = "2147696471"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 1a 58 91 06 28 ?? ?? ?? 06 20 ff 00 00 00 5f 28 ?? ?? ?? ?? 61 d2 9c 06 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BJ_2147696474_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BJ"
        threat_id = "2147696474"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 da 91 1f ?? 61 0c 03 8e b7 17 d6 8d ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 ?? ?? 11 ?? ?? 08 61 06 07 91 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BK_2147696475_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BK"
        threat_id = "2147696475"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 91 61 9c 00 11 ?? 17 d6 13 ?? 11 ?? 11 ?? 31 ?? ?? ?? 2b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BL_2147696476_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BL"
        threat_id = "2147696476"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 11 08 93 13 07 08 07 93 13 09 11 07 11 04 da 11 09 da 13 0a 06 11 08 11 0a 28 ?? ?? ?? ?? 9d 07 17 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BN_2147697290_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BN"
        threat_id = "2147697290"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 fe 0e 00 00 11 01 13 01 11 02 13 02 11 03 13 03 11 04 13 04 14 0a 2b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BM_2147697291_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BM"
        threat_id = "2147697291"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 75 73 65 72 33 32 2e 64 6c 6c 00 [0-16] 26 00 43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 42 61 73 65}  //weight: 1, accuracy: Low
        $x_1_2 = "_Encrypted$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BO_2147706459_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BO"
        threat_id = "2147706459"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#Schema" ascii //weight: 1
        $x_1_2 = "ConfusedByAttribute" ascii //weight: 1
        $x_1_3 = "ConfuserEx v0." ascii //weight: 1
        $x_1_4 = "add_AssemblyResolve" ascii //weight: 1
        $x_1_5 = "get_PixelFormat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BQ_2147707031_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BQ"
        threat_id = "2147707031"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {39 72 2c ef d7 f0 bd 14 bc 61 a8 e0 d8 53 27 fe 9f d3 7c 5b 16 e2 6b b9 f7 8d 0e 05 f7 30 64 dd d7 00 57 7d 5e 44 91 be 9e 16 ae ef ae 17 b7 4a ac b1 bb b3 18 0c af 1f fb 52 c1 be 13 61 74 bf c1 ea d7 2a cf 4e 9b 45}  //weight: 5, accuracy: High
        $x_1_2 = "WinHTTP" wide //weight: 1
        $x_1_3 = "Auto-Discovery" wide //weight: 1
        $x_1_4 = "Web Proxy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Obfuscator_RunPE_2147707633_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.RunPE.DzkiLLeR"
        threat_id = "2147707633"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        info = "DzkiLLeR: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DzkiLLeR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BU_2147707922_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BU"
        threat_id = "2147707922"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 06 08 91 7e ?? 00 00 04 08 7e ?? 00 00 04 8e b7 5d 91 61 9c 08 17 58}  //weight: 1, accuracy: Low
        $x_1_2 = {07 08 07 08 91 7e ?? 00 00 04 08 7e ?? 00 00 04 8e b7 5d 91 61 9c 08 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_MSIL_Obfuscator_BV_2147708253_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BV"
        threat_id = "2147708253"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 e5 07 28 1b 00 2b 12 ?? ?? ?? ?? 6f ?? ?? ?? ?? 1f ?? 61 d2 9c ?? 17 58 ?? ?? ?? 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {32 e5 06 28 1b 00 2b 12 ?? ?? ?? ?? 6f ?? ?? ?? ?? 1f ?? 61 d2 9c ?? 17 58 ?? ?? ?? 6f}  //weight: 1, accuracy: Low
        $x_1_3 = {32 e5 08 28 1b 00 2b 12 ?? ?? ?? ?? 6f ?? ?? ?? ?? 1f ?? 61 d2 9c ?? 17 58 ?? ?? ?? 6f}  //weight: 1, accuracy: Low
        $x_1_4 = {32 e5 09 28 1b 00 2b 12 ?? ?? ?? ?? 6f ?? ?? ?? ?? 1f ?? 61 d2 9c ?? 17 58 ?? ?? ?? 6f}  //weight: 1, accuracy: Low
        $x_1_5 = {67 65 74 5f 4c 65 6e 67 74 68 00 67 65 74 5f 43 68 61 72 73 00 4c 6f 61 64 00 67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 00 49 6e 76 6f 6b 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_MSIL_Obfuscator_BW_2147708654_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BW"
        threat_id = "2147708654"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 02 11 05 91 [0-2] 61 [0-3] 91 61 9c [0-2] 28 ?? 00 00 0a [0-4] 8e b7 17 da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BX_2147708675_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BX"
        threat_id = "2147708675"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 07 61 08 11 ?? 91 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BY_2147708696_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BY"
        threat_id = "2147708696"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 0c 06 16 07 6f ?? ?? ?? ?? 08 20 ff ff 00 00 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_BZ_2147708953_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.BZ"
        threat_id = "2147708953"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 5d 91 61 28 ?? 00 00 0a 6f ?? 00 00 0a 26 09 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_CA_2147708956_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.CA"
        threat_id = "2147708956"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 17 d6 0a 06 17 d6 0a 06 17 d6 0a 11 ?? 11 ?? 11 ?? 11 ?? 91 11 ?? 11 ?? 11 ?? 5d 91 61 9c 06 17 d6 0a 06 17 d6 0a 06 17 d6 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_CB_2147709396_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.CB!bit"
        threat_id = "2147709396"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 07 02 07 91 1f 0f 61 d2 9c 07 1f 0f 58 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Obfuscator_CD_2147711138_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Obfuscator.CD"
        threat_id = "2147711138"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 1f 4d 9c 11 ?? 17 1f 5a 9c 11 ?? 18 20 90 00 00 00 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

