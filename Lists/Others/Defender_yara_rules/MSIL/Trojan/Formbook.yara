rule Trojan_MSIL_Formbook_BA_2147753152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.BA!MTB"
        threat_id = "2147753152"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {95 58 20 ff 00 00 00 5f 13 0d 09 11 05 07 11 05 91 11 04 11 0d 95 61 28 ?? 00 00 0a 9c 11 05 17 58 13 05 00 11 05 6e 09 8e 69 6a fe 04}  //weight: 4, accuracy: Low
        $x_1_2 = {0a 0c 07 8e 69 8d ?? 00 00 01 0d 20 00 01 00 00 8d ?? 00 00 01 13 04 16 13 05 2b 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PD_2147754178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PD!MTB"
        threat_id = "2147754178"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 03 04 05 5d 05 58 05 5d 91 0a 2b 00 06 2a}  //weight: 2, accuracy: High
        $x_2_2 = {00 04 05 5d 05 58 05 5d 0a 03 06 91 0b 07 0e ?? 61 0e ?? 59 20 00 02 00 00 58 0c 08 0d 2b 00 09 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PD_2147754178_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PD!MTB"
        threat_id = "2147754178"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0c 2b 1f 06 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 26 08 18 d6 0c 08 07 31 dd 06 6f ?? 00 00 0a 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 16 9a 13 ?? 11 ?? 72 ?? ?? ?? 70 20 00 01 00 00 14 14 1a 8d 01 00 00 01 13 ?? 11 ?? 16 [0-2] a2 11 ?? 17 [0-2] a2 11 ?? 18 [0-2] a2 11 [0-10] 6f ?? 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_VN_2147759242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.VN!MTB"
        threat_id = "2147759242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 25 16 72 ?? ?? ?? 70 a2 25 17 7e ?? ?? ?? 04 a2 25 18 7e ?? ?? ?? 04 a2 0a 06 28 ?? ?? ?? 0a 00 06 73 ?? ?? ?? 06 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_VN_2147759242_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.VN!MTB"
        threat_id = "2147759242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 25 16 7e ?? ?? ?? 04 a2 25 17 7e ?? ?? ?? 04 a2 25 18 72 ?? ?? ?? 70 a2 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_VN_2147759242_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.VN!MTB"
        threat_id = "2147759242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 91 61 d2 81 ?? ?? ?? 01 00 06 17 58 0a 06 02 8e 69 fe ?? 0c 08 2d 15 00 02 06 8f ?? ?? ?? 01 25 71 ?? ?? ?? 01 7e ?? ?? ?? 04 06 1f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_VN_2147759242_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.VN!MTB"
        threat_id = "2147759242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0b 2b ?? 00 02 07 8f ?? ?? ?? 01 25 71 ?? ?? ?? 01 06 07 1f ?? 5d 91 61 d2 81 ?? ?? ?? 01 00 07 17 58 0b 07 02 8e 69 fe ?? 0d 09 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_VN_2147759242_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.VN!MTB"
        threat_id = "2147759242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 02 72 ?? ?? ?? 70 7d ?? ?? ?? 04 02 72 ?? ?? ?? 70 7d ?? ?? ?? 04 02 19 8d ?? ?? ?? 01 25 16 02 7b ?? ?? ?? 04 a2 25 17 02 7b ?? ?? ?? 04 a2 7d ?? ?? ?? 04 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_VN_2147759242_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.VN!MTB"
        threat_id = "2147759242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 00 7e ?? ?? ?? 04 0a 06 16 7e ?? ?? ?? 04 a2 06 17 7e ?? ?? ?? 04 a2 06 73 ?? ?? ?? 06 0b 02}  //weight: 1, accuracy: Low
        $x_1_2 = {04 0b 07 16 7e ?? ?? ?? 04 a2 07 17 7e ?? ?? ?? 04 a2 06 6f ?? ?? ?? 0a 16 9a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Formbook_VN_2147759242_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.VN!MTB"
        threat_id = "2147759242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 0a 06 16 02 28 ?? ?? ?? 06 a2 06 17 02 28 ?? ?? ?? 06 a2 06 18 72 ?? ?? ?? 70 a2 06 73 ?? ?? ?? 06 0b 2b ?? 07 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {01 0a 19 8d ?? ?? ?? 01 25 16 02 28 ?? ?? ?? 06 a2 25 17 02 28 ?? ?? ?? 06 a2 25 18 02 28 ?? ?? ?? 06 a2 0a 06 73 ?? ?? ?? 06 0b 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Formbook_VN_2147759242_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.VN!MTB"
        threat_id = "2147759242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_2 = "MathLibrary.Properties" ascii //weight: 1
        $x_1_3 = "StartGame" ascii //weight: 1
        $x_1_4 = "$486474cf-9038-41c2-855e-b7a6492b54ae" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_VN_2147759242_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.VN!MTB"
        threat_id = "2147759242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 0c 19 8d ?? ?? ?? 01 80 ?? ?? ?? 04 7e ?? ?? ?? 04 16 7e ?? ?? ?? 04 a2 7e ?? ?? ?? 04 17 7e ?? ?? ?? 04 a2 02 07 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 28 ?? ?? ?? 06 26 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {01 25 16 7e ?? ?? ?? 04 a2 25 17 7e ?? ?? ?? 04 a2 25 18 72 ?? ?? ?? 70 a2 73 ?? ?? ?? 06 0a 2a 05 00 19 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Formbook_MK_2147759892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MK!MTB"
        threat_id = "2147759892"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 02 07 91 6f ?? ?? ?? 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08 2d e8}  //weight: 1, accuracy: Low
        $x_1_2 = {13 05 16 13 06 00 09 11 05 16 11 05 8e 69 6f ?? ?? ?? 0a 13 06 07 11 05 16 11 06 6f ?? ?? ?? 0a 00 00 11 06 16 fe 02 13 09 11 09 2d d8}  //weight: 1, accuracy: Low
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_SS_2147765265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.SS!MTB"
        threat_id = "2147765265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 6a 53 00 70 0a 06 28 51 00 00 06 72 ef 53 00 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 2b 0b 73 1c 01 00 06 07 28 3f 01 00 06 28 28 00 00 0a 0c 73 9d 01 00 06 0d 09 73 83 01 00 06 28 ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_FH_2147767207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.FH!MTB"
        threat_id = "2147767207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$a808d42f-c248-49c0-932a-b89a85900e8e" ascii //weight: 20
        $x_20_2 = "$03b7d048-8014-4bf8-bc7b-05d497d5b645" ascii //weight: 20
        $x_20_3 = "$dce01c5a-0e3e-4eab-a31f-42fa1d09f647" ascii //weight: 20
        $x_20_4 = "$efd9aebe-f00a-4491-9b0e-94919b722754" ascii //weight: 20
        $x_20_5 = "$da725005-5c26-4376-ba26-2d210829b249" ascii //weight: 20
        $x_20_6 = "$e8160bbf-549f-4990-bb4d-b5c564607b89" ascii //weight: 20
        $x_1_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_9 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_10 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_11 = "CreateInstance" ascii //weight: 1
        $x_1_12 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_13 = "Activator" ascii //weight: 1
        $x_1_14 = "DebuggableAttribute" ascii //weight: 1
        $x_1_15 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_FB_2147770189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.FB!MTB"
        threat_id = "2147770189"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$67cc88cb-4070-4dc6-aa8e-e6d38ec2063c" ascii //weight: 20
        $x_20_2 = "ShitBrick_Tool.Resources.resources" ascii //weight: 20
        $x_1_3 = "YAY! FIX DEPENDANCY ISSUE WITH DOTNETBAR2" ascii //weight: 1
        $x_1_4 = "ShitBrick Tool" ascii //weight: 1
        $x_1_5 = "DownloadFile" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_FC_2147770280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.FC!MTB"
        threat_id = "2147770280"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$d408c265-af3e-438f-b6af-9bdc58665de6" ascii //weight: 20
        $x_20_2 = "ColorPalette.Properties.Resources" ascii //weight: 20
        $x_1_3 = "CropedImage" ascii //weight: 1
        $x_1_4 = "information.txt" ascii //weight: 1
        $x_1_5 = "outlook.txt" ascii //weight: 1
        $x_1_6 = "passwords.txt" ascii //weight: 1
        $x_1_7 = "Wallets/Exodus" ascii //weight: 1
        $x_1_8 = "cookie_list.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 6 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_AMP_2147773164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMP!MTB"
        threat_id = "2147773164"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hsxiJoLMpnBJpENheXOvRLFZBGhz" ascii //weight: 1
        $x_1_2 = "gUMmYhRCxuymaCpyXruEKznsrpKp" ascii //weight: 1
        $x_1_3 = "dAmaleNhskeHlICoegLAKRnMLWTgA" ascii //weight: 1
        $x_1_4 = "VTzJBpwceYtnuyFXRTqPNbGmqOYO" ascii //weight: 1
        $x_1_5 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_6 = "gUMmYhRCxuymaCpyXruEKznsrpKp.resources" ascii //weight: 1
        $x_1_7 = "http://tensorflow.org/docs/" wide //weight: 1
        $x_1_8 = "STAThreadAttribute" ascii //weight: 1
        $x_1_9 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DA_2147775558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DA!MTB"
        threat_id = "2147775558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$95678bb2-5452-466e-8099-0b15969ade19" ascii //weight: 1
        $x_1_2 = "POS.My.Resources" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_4 = "get_Clipboard" ascii //weight: 1
        $x_1_5 = "get_WhiteSmoke" ascii //weight: 1
        $x_1_6 = "Facebook" ascii //weight: 1
        $x_1_7 = "Password" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DB_2147775559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DB!MTB"
        threat_id = "2147775559"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$A3AC9DDF-205B-4AC0-B1B5-AB0223C3E992" ascii //weight: 1
        $x_1_2 = "get_SeaGreen" ascii //weight: 1
        $x_1_3 = "Staff_Salary" ascii //weight: 1
        $x_1_4 = "Colloquium" ascii //weight: 1
        $x_1_5 = "getFees" ascii //weight: 1
        $x_1_6 = "Toyota" ascii //weight: 1
        $x_1_7 = "Camry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DB_2147775559_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DB!MTB"
        threat_id = "2147775559"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 06 07 16 20 ?? ?? ?? ?? 6f ?? ?? ?? 0a 0d 09 16 fe 02 13 04 11 04 2c 0c 00 08 07 16 09 6f ?? ?? ?? ?? ?? ?? ?? ?? 16 fe 02 13 05 11 05 2d}  //weight: 10, accuracy: Low
        $x_1_2 = "GZIDEKKKK" ascii //weight: 1
        $x_1_3 = "DES_Decrypt" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DC_2147775560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DC!MTB"
        threat_id = "2147775560"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MisterHook" ascii //weight: 1
        $x_1_2 = "HookKey" ascii //weight: 1
        $x_1_3 = "keybd_event" ascii //weight: 1
        $x_1_4 = "mouse_event" ascii //weight: 1
        $x_1_5 = "KeyboardHookStruct" ascii //weight: 1
        $x_1_6 = "MouseHookStruct" ascii //weight: 1
        $x_1_7 = "PathToSave" ascii //weight: 1
        $x_1_8 = "SaveRecordToFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DD_2147775941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DD!MTB"
        threat_id = "2147775941"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 06 07 16 20 ?? ?? ?? ?? 6f ?? ?? ?? ?? 0d 09 16 fe 02 13 04 11 04 2c 0c 00 08 07 16 09 6f ?? ?? ?? ?? ?? ?? ?? ?? 16 fe 02 13 05 11 05 2d}  //weight: 10, accuracy: Low
        $x_1_2 = "GZIDEKKKK" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DD_2147775941_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DD!MTB"
        threat_id = "2147775941"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$b986dc75-c524-43b3-9d06-ba460c8fedf5" ascii //weight: 1
        $x_1_2 = "CaptureScreen.Properties.Resources" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_4 = "Capture mouse cursor" ascii //weight: 1
        $x_1_5 = "BackgroundWorker" ascii //weight: 1
        $x_1_6 = "kryptonButton" ascii //weight: 1
        $x_1_7 = "SonicMaster" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DF_2147775942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DF!MTB"
        threat_id = "2147775942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$F97525BE-A3F9-4862-8A1E-D6098BE7BE7C" ascii //weight: 1
        $x_1_2 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "ConnectionString" ascii //weight: 1
        $x_1_5 = "SendOrPostCallback" ascii //weight: 1
        $x_1_6 = "Staff_Passcode" ascii //weight: 1
        $x_1_7 = "Milky Lane" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DJ_2147776071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DJ!MTB"
        threat_id = "2147776071"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$729acc5c-aa39-43a2-a6cd-d490f5aa9f46" ascii //weight: 1
        $x_1_2 = "get_Manager_password" ascii //weight: 1
        $x_1_3 = "get_Goods_amount" ascii //weight: 1
        $x_1_4 = "Warehouse" ascii //weight: 1
        $x_1_5 = "Passwordtext" ascii //weight: 1
        $x_1_6 = "123456" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DJ_2147776071_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DJ!MTB"
        threat_id = "2147776071"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$628d6b64-163e-471d-8227-5d43386512e1" ascii //weight: 1
        $x_1_2 = "screencapturer.log" ascii //weight: 1
        $x_1_3 = "MouseKeyTriggers" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "ScreenCapturer.Properties" ascii //weight: 1
        $x_1_6 = "Logger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DH_2147776176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DH!MTB"
        threat_id = "2147776176"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$db5cf35e-dad9-4c92-8279-a67b5b95a1c0" ascii //weight: 1
        $x_1_2 = "Social_Club.Resources" ascii //weight: 1
        $x_1_3 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_4 = "ICryptoTransform" ascii //weight: 1
        $x_1_5 = "set_HideSelection" ascii //weight: 1
        $x_1_6 = "get_Connection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DI_2147776177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DI!MTB"
        threat_id = "2147776177"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChatMessageQueue.Chat.resources" ascii //weight: 1
        $x_1_2 = "Core.Numero" ascii //weight: 1
        $x_1_3 = "directDownloadUrl" ascii //weight: 1
        $x_1_4 = "CreateQueue" ascii //weight: 1
        $x_1_5 = "Chat Queue" ascii //weight: 1
        $x_1_6 = "Romans" ascii //weight: 1
        $x_1_7 = "@uwec.edu" ascii //weight: 1
        $x_1_8 = "biblija.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DM_2147776465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DM!MTB"
        threat_id = "2147776465"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$733e757c-fc03-4d45-9190-d769e7ac2e94" ascii //weight: 1
        $x_1_2 = "Backup Successfully Restored!!!" ascii //weight: 1
        $x_1_3 = "Pathology.Resources" ascii //weight: 1
        $x_1_4 = "StockMaster" ascii //weight: 1
        $x_1_5 = "Patient_Master" ascii //weight: 1
        $x_1_6 = "DiseaseMstr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DN_2147776466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DN!MTB"
        threat_id = "2147776466"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "milestone2.Resources" ascii //weight: 1
        $x_1_2 = "group4ConnectionString" ascii //weight: 1
        $x_1_3 = "get_Connection" ascii //weight: 1
        $x_1_4 = "SplashScreen" ascii //weight: 1
        $x_1_5 = "Cashier" ascii //weight: 1
        $x_1_6 = "Butchery" ascii //weight: 1
        $x_1_7 = "smtp.gmail.com" ascii //weight: 1
        $x_1_8 = "LockHolder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DP_2147776467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DP!MTB"
        threat_id = "2147776467"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$a16abbb4-985b-4db2-a80c-21268b26c73d" ascii //weight: 1
        $x_1_2 = "get_CurrentDomain" ascii //weight: 1
        $x_1_3 = "ToBase64String" ascii //weight: 1
        $x_1_4 = "ReverseDecode" ascii //weight: 1
        $x_1_5 = "StormKitty" ascii //weight: 1
        $x_1_6 = "LimerBoy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DQ_2147776580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DQ!MTB"
        threat_id = "2147776580"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$54ab31cd-1526-46a9-bdb4-a79647281295" ascii //weight: 1
        $x_1_2 = "Milk_Dairy.Resources" ascii //weight: 1
        $x_1_3 = "CollectMilk" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "GetResourceString" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DQ_2147776580_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DQ!MTB"
        threat_id = "2147776580"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$efeb886f-2926-4976-a76a-1c496da6a22d" ascii //weight: 1
        $x_1_2 = "Renda_Lonnie.My.Resources" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_5 = "writeToFile" ascii //weight: 1
        $x_1_6 = "Interlocked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DV_2147776581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DV!MTB"
        threat_id = "2147776581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Medical_Laboratory.My.Resources" ascii //weight: 1
        $x_1_2 = "Medical_Laboratory.Bills.resources" ascii //weight: 1
        $x_1_3 = "FromBase64CharArray" ascii //weight: 1
        $x_1_4 = "GetDomain" ascii //weight: 1
        $x_1_5 = "IsLogging" ascii //weight: 1
        $x_1_6 = "Hotplates" ascii //weight: 1
        $x_1_7 = "dnspy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DV_2147776581_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DV!MTB"
        threat_id = "2147776581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TableAdapter.My.Resources" ascii //weight: 1
        $x_1_2 = "TableAdapter.Resources.resources" ascii //weight: 1
        $x_1_3 = "get_ConnectionString" ascii //weight: 1
        $x_1_4 = "Interlocked" ascii //weight: 1
        $x_1_5 = "isLOSBlocking" ascii //weight: 1
        $x_1_6 = "psykerpowers" ascii //weight: 1
        $x_1_7 = "Canon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DV_2147776581_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DV!MTB"
        threat_id = "2147776581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QuNectRazor.My.Resources" ascii //weight: 1
        $x_1_2 = "QuNectRazor.frmRazor.resources" ascii //weight: 1
        $x_1_3 = "connectionString" ascii //weight: 1
        $x_1_4 = "razor_Load" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "SoapNmtoken" ascii //weight: 1
        $x_1_7 = "get_Directory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DO_2147776583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DO!MTB"
        threat_id = "2147776583"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ReepahDataSet2BindingSource" ascii //weight: 1
        $x_1_2 = "ReepahConnectionString" ascii //weight: 1
        $x_1_3 = "ReepahDataSet" ascii //weight: 1
        $x_1_4 = "get_ConnectionString" ascii //weight: 1
        $x_1_5 = "Interlocked" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
        $x_1_7 = "CompareString" ascii //weight: 1
        $x_1_8 = ".\"4#7&<'A(F)I*L+N,P-U.Z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DS_2147776584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DS!MTB"
        threat_id = "2147776584"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ASM_PS.frmKhachHang.resources" ascii //weight: 1
        $x_1_2 = "ASM_PS.Resources" ascii //weight: 1
        $x_1_3 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_4 = "DebuggingModes" ascii //weight: 1
        $x_1_5 = "DisableCheck" ascii //weight: 1
        $x_1_6 = "remove_MouseMove" ascii //weight: 1
        $x_1_7 = "SetDesktopLocation" ascii //weight: 1
        $x_1_8 = "inchat.kro.kr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DT_2147776585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DT!MTB"
        threat_id = "2147776585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ScreenCapturer.Properties.Resources" ascii //weight: 1
        $x_1_2 = "ScreenCapturer.exe" ascii //weight: 1
        $x_1_3 = "CompilationRelaxationsAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "CreateDecryptor" ascii //weight: 1
        $x_1_9 = "GetDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DU_2147776659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DU!MTB"
        threat_id = "2147776659"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$537f8724-5756-43ec-b229-345e450f356b" ascii //weight: 1
        $x_1_2 = "DSMS_DBConnectionString" ascii //weight: 1
        $x_1_3 = "DSMS.My.Resources" ascii //weight: 1
        $x_1_4 = "D S Damat Online" ascii //weight: 1
        $x_1_5 = "Hostel and Mess Fees" ascii //weight: 1
        $x_1_6 = "DSMS.Flet" ascii //weight: 1
        $x_1_7 = "Adhar_Number" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DW_2147776660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DW!MTB"
        threat_id = "2147776660"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$30d4aa3a-afb6-4765-ba18-f2364470e34f" ascii //weight: 10
        $x_10_2 = "$1eef5f76-62f2-4820-934c-91781f51ee86" ascii //weight: 10
        $x_10_3 = "$f5da78b2-7b14-4824-9389-00a87e72db4c" ascii //weight: 10
        $x_1_4 = "VB_blackjack.My.Resources" ascii //weight: 1
        $x_1_5 = "game.My.Resources" ascii //weight: 1
        $x_1_6 = "Taquin.My.Resources" ascii //weight: 1
        $x_1_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_11 = "GetResourceString" ascii //weight: 1
        $x_1_12 = "DebuggableAttribute" ascii //weight: 1
        $x_1_13 = "get_GetInstance" ascii //weight: 1
        $x_1_14 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_15 = "get_Computer" ascii //weight: 1
        $x_1_16 = "DebuggerHiddenAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_DX_2147776661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DX!MTB"
        threat_id = "2147776661"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$3ea81680-a406-495e-8714-6fa133adc4b9" ascii //weight: 1
        $x_1_2 = "FmgEdit.DB.resources" ascii //weight: 1
        $x_1_3 = "FmgEdit.card_swap.resources" ascii //weight: 1
        $x_1_4 = "FromBase64CharArray" ascii //weight: 1
        $x_1_5 = "LoadFromFile" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DY_2147776662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DY!MTB"
        threat_id = "2147776662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$0FEB2D64-EF5F-4FE0-B18A-87140BC2061D" ascii //weight: 10
        $x_10_2 = "$0A0AA70A-86C1-49C3-A713-3D10A60EEC98" ascii //weight: 10
        $x_1_3 = "VB_blackjack.My.Resources" ascii //weight: 1
        $x_1_4 = "Health_Point_Game.My.Resources" ascii //weight: 1
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_9 = "GetResourceString" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "get_GetInstance" ascii //weight: 1
        $x_1_12 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_13 = "get_Computer" ascii //weight: 1
        $x_1_14 = "DebuggerHiddenAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_DZ_2147776663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DZ!MTB"
        threat_id = "2147776663"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$995597c7-e07d-40da-9cea-72a7476303fd" ascii //weight: 10
        $x_1_2 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_5 = "GetResourceString" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "get_GetInstance" ascii //weight: 1
        $x_1_8 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_9 = "get_Computer" ascii //weight: 1
        $x_1_10 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_11 = "Battletech.Resources" ascii //weight: 1
        $x_1_12 = "Pilot Piloting" ascii //weight: 1
        $x_1_13 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_14 = "SplashScreen1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_ED_2147776884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ED!MTB"
        threat_id = "2147776884"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$446cc4d4-2a93-4c90-bf45-28d7ed1bf2da" ascii //weight: 10
        $x_1_2 = "PropertyAccessor.Resources" ascii //weight: 1
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_5 = "Activator" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "CreateInstance" ascii //weight: 1
        $x_1_8 = "DebuggerStepThroughAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_ED_2147776884_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ED!MTB"
        threat_id = "2147776884"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$1E9F460D-28EF-4761-A69D-58021293D5C8" ascii //weight: 10
        $x_10_2 = "$a8a19249-4fe0-478b-bacf-2b2b55a49ac3" ascii //weight: 10
        $x_1_3 = "FormatterSink" ascii //weight: 1
        $x_1_4 = "Painter.Form1.resources" ascii //weight: 1
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_8 = "get_CurrentDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_DK_2147776885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DK!MTB"
        threat_id = "2147776885"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$e19c81b1-37ec-4bba-88de-ba4ddce20a01" ascii //weight: 1
        $x_1_2 = "screencapture.Properties.Resources" ascii //weight: 1
        $x_1_3 = "Quit: Ctrl + Alt + Shift + Q" ascii //weight: 1
        $x_1_4 = "autorestart" ascii //weight: 1
        $x_1_5 = "get_FtpAddress" ascii //weight: 1
        $x_1_6 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_EA_2147776886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EA!MTB"
        threat_id = "2147776886"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$04571553-1360-4802-92c5-c0edc48291ff" ascii //weight: 20
        $x_20_2 = "$b6666200-57b0-40b8-a7db-ad889539c97d" ascii //weight: 20
        $x_20_3 = "$48b4e55d-fbd1-44b3-b333-1678fd484ca4" ascii //weight: 20
        $x_1_4 = "Event_Participation.My.Resources" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "Free_Sale.My.Resources" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_8 = "ScreenCaCa.Properties.Resources" ascii //weight: 1
        $x_1_9 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "DebuggerHiddenAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_EB_2147776887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EB!MTB"
        threat_id = "2147776887"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$0FEB2D64-EF5F-4FE0-B18A-87140BC2061D" ascii //weight: 20
        $x_20_2 = "$aa39a3d4-7a9c-4386-988a-20f98388dd13" ascii //weight: 20
        $x_20_3 = "$30b79d63-edaf-4eca-a7dc-7af998be2727" ascii //weight: 20
        $x_1_4 = "FoxGameOfLife.Resources" ascii //weight: 1
        $x_1_5 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_6 = "RestaurantManagementSystem.Properties.Resources" ascii //weight: 1
        $x_1_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_8 = "KTVManagement.My.Resources" ascii //weight: 1
        $x_1_9 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "DebuggerBrowsableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_EC_2147776888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EC!MTB"
        threat_id = "2147776888"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$28ff0c8b-949e-4ba6-8b49-fe8885c22e5f" ascii //weight: 20
        $x_20_2 = "$5877c168-1f58-495b-b960-13be269a599f" ascii //weight: 20
        $x_20_3 = "$c4667df7-21b8-478c-ab03-311c3cbc48d3" ascii //weight: 20
        $x_1_4 = "SnakeGamePOO.Resources" ascii //weight: 1
        $x_1_5 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_6 = "Studioborne.My.Resources" ascii //weight: 1
        $x_1_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_8 = "Restaurant.My.Resources" ascii //weight: 1
        $x_1_9 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_12 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 6 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_EF_2147777287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EF!MTB"
        threat_id = "2147777287"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$5c66dec4-0d23-4981-9878-0afa8de8696f" ascii //weight: 20
        $x_20_2 = "$af4883cf-1507-4495-b599-a25eb82cd571" ascii //weight: 20
        $x_20_3 = "$2423b512-5e0c-49b1-801b-c9b7c23b2408" ascii //weight: 20
        $x_20_4 = "$17d476f8-2f6c-4399-a7f5-6071ed16d811" ascii //weight: 20
        $x_5_5 = "Framwork.Properties.Resources" ascii //weight: 5
        $x_5_6 = "xxxxxxxxxxxxxx.My.Resources" ascii //weight: 5
        $x_5_7 = "li.My.Resources" ascii //weight: 5
        $x_5_8 = "Process_Monitor.Properties.Resources" ascii //weight: 5
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_11 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_12 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_13 = "CreateInstance" ascii //weight: 1
        $x_1_14 = "Activator" ascii //weight: 1
        $x_1_15 = "RSM_Decrypt" ascii //weight: 1
        $x_1_16 = "get_Crypted" ascii //weight: 1
        $x_1_17 = "get_EntryPoint" ascii //weight: 1
        $x_1_18 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 9 of ($x_1_*))) or
            ((1 of ($x_20_*) and 9 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_EG_2147777288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EG!MTB"
        threat_id = "2147777288"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$0cff0d70-a1a4-425a-9733-d724ea623f2e" ascii //weight: 20
        $x_20_2 = "$a43c2eb5-5e60-4612-83cf-1db675e1f500" ascii //weight: 20
        $x_20_3 = "$3afe1cf9-ea74-4c54-9305-026b7d000875" ascii //weight: 20
        $x_20_4 = "$e009b5e3-28a2-4420-bdfa-01e6cefbccb2" ascii //weight: 20
        $x_1_5 = "VisualEngine.Resources" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_7 = "memory.My.Resources" ascii //weight: 1
        $x_1_8 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_9 = "SafeCertContextHandle.My.Resources" ascii //weight: 1
        $x_1_10 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_11 = "projectManagementSystem.My.Resources" ascii //weight: 1
        $x_1_12 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_13 = "CreateInstance" ascii //weight: 1
        $x_1_14 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_15 = "Activator" ascii //weight: 1
        $x_1_16 = "connectionString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_DL_2147777538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DL!MTB"
        threat_id = "2147777538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$f065640e-97e2-4179-abdd-59b3a24bd0b2" ascii //weight: 1
        $x_1_2 = "Programming Project" ascii //weight: 1
        $x_1_3 = "File missing!!!" ascii //weight: 1
        $x_1_4 = "@telephone" ascii //weight: 1
        $x_1_5 = "Cyprus" ascii //weight: 1
        $x_1_6 = "up_to_10_domains" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_EH_2147777539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EH!MTB"
        threat_id = "2147777539"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$e635acd5-2519-4759-8406-05996a8615bc" ascii //weight: 20
        $x_20_2 = "$6dd702ca-6283-4629-b544-598616a52b93" ascii //weight: 20
        $x_20_3 = "$6a88065c-663a-4f85-b076-265e50b81165" ascii //weight: 20
        $x_1_4 = "SingleScreenCapture.Properties.Resources" ascii //weight: 1
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "ImgTrackTrimmer.Properties.Resources" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "CMS_TIME_UNIT_TYPE.Resources" ascii //weight: 1
        $x_1_9 = "CreateInstance" ascii //weight: 1
        $x_1_10 = "Activator" ascii //weight: 1
        $x_1_11 = "GetDomain" ascii //weight: 1
        $x_1_12 = "GetResourceString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_EK_2147777541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EK!MTB"
        threat_id = "2147777541"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$E0ACDE0D-5525-450B-9805-0DD7D2766CE5" ascii //weight: 20
        $x_20_2 = "$c56a6385-23c9-4af9-8a5f-accf8ba07616" ascii //weight: 20
        $x_20_3 = "$83923057-de81-413b-9e23-9da342e8430b" ascii //weight: 20
        $x_20_4 = "$c2934561-035a-4a99-b861-336f50318173" ascii //weight: 20
        $x_1_5 = "ScopeAction.My.Resources" ascii //weight: 1
        $x_1_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_7 = "Game.My.Resources" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "SafeViewOfFileHandle.My.Resources" ascii //weight: 1
        $x_1_10 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_11 = "BaseConfigHandler.My.Resources" ascii //weight: 1
        $x_1_12 = "CreateInstance" ascii //weight: 1
        $x_1_13 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_EM_2147777727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EM!MTB"
        threat_id = "2147777727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$a27ccf07-2bd5-40dc-9679-505dca99faf4" ascii //weight: 10
        $x_1_2 = "GESTTION_des_HOTEL" ascii //weight: 1
        $x_1_3 = "GetDomain" ascii //weight: 1
        $x_1_4 = "WebRequest" ascii //weight: 1
        $x_1_5 = "Activator" ascii //weight: 1
        $x_1_6 = "GetResourceString" ascii //weight: 1
        $x_1_7 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_EM_2147777727_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EM!MTB"
        threat_id = "2147777727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$52803763-0c38-45d0-8df9-79be41327f72" ascii //weight: 10
        $x_1_2 = "Calculator.MainMenu.resources" ascii //weight: 1
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_5 = "Activate" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "GetDomain" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_EM_2147777727_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EM!MTB"
        threat_id = "2147777727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "GQkiL.pdb" ascii //weight: 3
        $x_3_2 = "aHR0cDovL29seXBhdGguY29tL1FzUm9BLmV4ZQ==" ascii //weight: 3
        $x_3_3 = "DownloadData" ascii //weight: 3
        $x_3_4 = "get_ExecutablePath" ascii //weight: 3
        $x_3_5 = "DesignPatterns.GangOfFour.Structural.Bridge" ascii //weight: 3
        $x_3_6 = "testingASPNETMVCWebAPI" ascii //weight: 3
        $x_3_7 = "CommonDesignPatterns.introDotNetCoreWithMVC" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_EL_2147777741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EL!MTB"
        threat_id = "2147777741"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$0cceceff-f29b-40b3-b57b-c133c63f4bf6" ascii //weight: 10
        $x_10_2 = "PublisherMembershipCondition.My.Resources" ascii //weight: 10
        $x_5_3 = "DebuggerBrowsableState" ascii //weight: 5
        $x_5_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 5
        $x_5_5 = "DebuggableAttribute" ascii //weight: 5
        $x_5_6 = "DebuggerBrowsableAttribute" ascii //weight: 5
        $x_1_7 = "CreateInstance" ascii //weight: 1
        $x_1_8 = "Activator" ascii //weight: 1
        $x_1_9 = "Create__Instance__" ascii //weight: 1
        $x_1_10 = "GetInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_EI_2147778052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EI!MTB"
        threat_id = "2147778052"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$ac045e25-5d9e-42b8-a1ce-4c3a95960eae" ascii //weight: 10
        $x_1_2 = "stub_2.netrsrc.resources" ascii //weight: 1
        $x_1_3 = "PELock Software" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = ".netshrink stub" ascii //weight: 1
        $x_1_7 = "ClassLibrary1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_EJ_2147778053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EJ!MTB"
        threat_id = "2147778053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$8a111536-1bf4-4294-af80-5e1328412f32" ascii //weight: 10
        $x_10_2 = "$368f3cbf-7c22-4b49-ab2c-43d9a5632b76" ascii //weight: 10
        $x_5_3 = "get_CurrentDomain" ascii //weight: 5
        $x_5_4 = "CreateInstance" ascii //weight: 5
        $x_5_5 = "Activator" ascii //weight: 5
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "HideModuleNameAttribute" ascii //weight: 1
        $x_1_11 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_EN_2147778054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EN!MTB"
        threat_id = "2147778054"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$a66a5494-c5f5-4e92-ac14-032661688b8d" ascii //weight: 20
        $x_20_2 = "$41d10c1a-6a68-42da-899d-eda166e531d0" ascii //weight: 20
        $x_20_3 = "$85193a6a-3bcd-4636-9f4a-bc79fc477732" ascii //weight: 20
        $x_20_4 = "$6a8e413f-c5e1-48c8-974a-f3ce770e4295" ascii //weight: 20
        $x_1_5 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_7 = "ToBase64String" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "CreateInstance" ascii //weight: 1
        $x_1_10 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 6 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_EP_2147778056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EP!MTB"
        threat_id = "2147778056"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$d29b994b-8c11-4fed-9f11-4e94966d15b3" ascii //weight: 20
        $x_20_2 = "$05FF5DCF-3066-4ED9-A95A-0EDA10B05990" ascii //weight: 20
        $x_20_3 = "$bba005ad-79a0-4d70-bba7-3f2a86f9425a" ascii //weight: 20
        $x_20_4 = "$06f8ab74-a5cc-4ffd-afd0-e30ea955ed39" ascii //weight: 20
        $x_1_5 = "Star_Crew_Server.Resources" ascii //weight: 1
        $x_1_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_7 = "TWCalculator.Resources" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_9 = "Archery_Management_System.Resources" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "IDynamicMessage.Resources" ascii //weight: 1
        $x_1_12 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_13 = "CreateInstance" ascii //weight: 1
        $x_1_14 = "Activator" ascii //weight: 1
        $x_1_15 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_EQ_2147778059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EQ!MTB"
        threat_id = "2147778059"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$e392740d-2dfa-4a95-ad21-56bbff79e0d0" ascii //weight: 20
        $x_20_2 = "$008a850e-d420-4655-a135-74d9643e2349" ascii //weight: 20
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "StoKOdnomuControl.Resources" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_6 = "DatabaseTestApplication2.Resources" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "DebuggingModes" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_EE_2147778079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EE!MTB"
        threat_id = "2147778079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$68a8b8f3-4e11-4b3e-a19e-f1d3d4ed8161" ascii //weight: 1
        $x_1_2 = "26fc2.resources" ascii //weight: 1
        $x_1_3 = "get_CurrentDomain" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "frozen" ascii //weight: 1
        $x_1_6 = "1.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_EO_2147778226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EO!MTB"
        threat_id = "2147778226"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$97ec14cd-8378-4f8e-91aa-474e2bd015b7" ascii //weight: 20
        $x_1_2 = "Professional_Editor.CoreMain.resources" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "CreateInstance" ascii //weight: 1
        $x_1_8 = "Activator" ascii //weight: 1
        $x_1_9 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_ER_2147778228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ER!MTB"
        threat_id = "2147778228"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$5f1d9092-8cbb-4e73-b26c-80a3c1d7e1f7" ascii //weight: 20
        $x_20_2 = "$dec9efef-dfad-49e0-aaef-3322c983a256" ascii //weight: 20
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "FormsPrintScalingBlurryIssue.SinkStack.resources" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_6 = "ApplicationTrustManager.My.Resources" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_8 = "CreateInstance" ascii //weight: 1
        $x_1_9 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_BK_2147778303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.BK!MTB"
        threat_id = "2147778303"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 1f 10 62 0f 00 28 ?? 00 00 0a 1e 62 60 0f 00 28 ?? 00 00 0a 60 0a 03 19 8d ?? 00 00 01 25 16 06 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 06 1e 63 20 ff 00 00 00 5f d2 9c 25 18 06 20 ff 00 00 00 5f d2 9c 6f}  //weight: 4, accuracy: Low
        $x_1_2 = {02 06 07 28 ?? 00 00 06 0c 08 03 04 28 ?? 00 00 06 00 00 07 17 58 0b 07 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_ES_2147778326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ES!MTB"
        threat_id = "2147778326"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$253fb59b-745e-4a2b-8b07-926364277f24" ascii //weight: 20
        $x_20_2 = "$a15c5663-dc5b-4fcd-a347-9e7a9c8bec05" ascii //weight: 20
        $x_20_3 = "$d2845b89-8300-4c74-8dc1-61c5f3e28a3e" ascii //weight: 20
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "Living_Story.Resources" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "GalleryUploader.Properties.Resources" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_9 = "FormsFun.My.Resources" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_ET_2147778400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ET!MTB"
        threat_id = "2147778400"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$9fae60eb-9552-43a7-b7e5-dd33298c57da" ascii //weight: 20
        $x_20_2 = "$2cae4526-dfd5-4f11-ae2e-eb350df42691" ascii //weight: 20
        $x_1_3 = "DANG_NHAP_FORM" ascii //weight: 1
        $x_1_4 = "TargetFrameworkAttribute" ascii //weight: 1
        $x_1_5 = "get_ConnectionString" ascii //weight: 1
        $x_1_6 = "GetDomain" ascii //weight: 1
        $x_1_7 = "CreateInstance" ascii //weight: 1
        $x_1_8 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_ET_2147778400_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ET!MTB"
        threat_id = "2147778400"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeyedCollection.My.Resources" ascii //weight: 1
        $x_1_2 = "KeyedCollection.PendingWO.resources" ascii //weight: 1
        $x_1_3 = "Dahlkemper" ascii //weight: 1
        $x_1_4 = "Power Transformer" ascii //weight: 1
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_8 = "CreateInstance" ascii //weight: 1
        $x_1_9 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_EU_2147778544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EU!MTB"
        threat_id = "2147778544"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "StaggeringIsometricMap.Resources" ascii //weight: 20
        $x_20_2 = "SistemaVentas.Resources.resources" ascii //weight: 20
        $x_20_3 = "FTPLister.My.Resources" ascii //weight: 20
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "Suyeon Staggering Isometric Map" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "Sistema de Ventas MU" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_9 = "Devolepors@gmal.com" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 6 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_EV_2147778548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EV!MTB"
        threat_id = "2147778548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$a1baad2d-9bb8-4df9-b483-58ded47a0158" ascii //weight: 20
        $x_20_2 = "$7e1aa602-16dc-451a-8e54-17c9f959a19c" ascii //weight: 20
        $x_20_3 = "$C521A1A3-558B-461A-9BBB-753E6FD8D82F" ascii //weight: 20
        $x_10_4 = "CreateInstance" ascii //weight: 10
        $x_10_5 = "Activator" ascii //weight: 10
        $x_1_6 = "x000.My.Resources" ascii //weight: 1
        $x_1_7 = "gUMmYhRCxuymaCpyXruEKznsrpKp.resources" ascii //weight: 1
        $x_1_8 = "WinformsUtils.My.Resources" ascii //weight: 1
        $x_1_9 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_10 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_11 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_12 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_13 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_14 = "DebuggableAttribute" ascii //weight: 1
        $x_1_15 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*) and 1 of ($x_10_*))) or
            ((3 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_EW_2147778778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EW!MTB"
        threat_id = "2147778778"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$9a152371-76ad-40f3-ad45-879dcb147a5d" ascii //weight: 20
        $x_20_2 = "$7ec85c2d-d135-4aa8-ae22-6ca5537a10a4" ascii //weight: 20
        $x_20_3 = "$13dd038e-6d61-4d4f-a921-c59aba975077" ascii //weight: 20
        $x_20_4 = "$b6d43005-ff9a-4287-8a89-3f6fc43683b4" ascii //weight: 20
        $x_1_5 = "MoInk3.Resources.resources" ascii //weight: 1
        $x_1_6 = "_3.My.Resources" ascii //weight: 1
        $x_1_7 = "_2048.frmIntro.resources" ascii //weight: 1
        $x_1_8 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_9 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_10 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_11 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_12 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_13 = "DebuggableAttribute" ascii //weight: 1
        $x_1_14 = "DebuggingModes" ascii //weight: 1
        $x_1_15 = "CreateInstance" ascii //weight: 1
        $x_1_16 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_EX_2147778852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EX!MTB"
        threat_id = "2147778852"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$840e51c1-f39c-4218-966a-d8db0e5b9549" ascii //weight: 20
        $x_1_2 = "SocketServerForm.My.Resources" ascii //weight: 1
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_7 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "DebuggingModes" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_EY_2147779330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EY!MTB"
        threat_id = "2147779330"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 02 26 16 20}  //weight: 1, accuracy: High
        $x_1_2 = {70 15 16 28 2e 00 00 0a 80 0b 00 00 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 39 ?? ?? ?? ?? 26 20 ?? ?? ?? ?? 38}  //weight: 1, accuracy: Low
        $x_1_3 = {04 17 9a 28 2f 00 00 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 06 80 0c 00 00 04}  //weight: 1, accuracy: Low
        $x_1_4 = {20 e4 04 00 00 28 ?? ?? ?? ?? 7e 0b 00 00 04 17 9a 6f ?? ?? ?? 0a 26}  //weight: 1, accuracy: Low
        $x_1_5 = {38 2a 00 00 00 20 ?? ?? ?? ?? fe 0e 00 00 fe 0c 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_EZ_2147779631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EZ!MTB"
        threat_id = "2147779631"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "$e0ca255f-ccf1-44d1-8d64-bc1d16d06a9c" ascii //weight: 30
        $x_30_2 = "$a5ff5b7b-dc8f-4ed1-a2a1-3a97baa48bdf" ascii //weight: 30
        $x_10_3 = "CreateInstance" ascii //weight: 10
        $x_10_4 = "Activator" ascii //weight: 10
        $x_1_5 = "a2e4a00f377f.Resources.resources" ascii //weight: 1
        $x_1_6 = "StageOpvolging.Form1.resources" ascii //weight: 1
        $x_1_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_9 = "HotelUtility" ascii //weight: 1
        $x_1_10 = "WebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_30_*) and 2 of ($x_10_*))) or
            ((2 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_DE_2147779753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DE!MTB"
        threat_id = "2147779753"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$df1f6e61-0228-42d0-9cc9-bdf6c83e5611" ascii //weight: 1
        $x_1_2 = "databaseConnectionString" ascii //weight: 1
        $x_1_3 = "studentsConnectionString" ascii //weight: 1
        $x_1_4 = "Student_Management" ascii //weight: 1
        $x_1_5 = "ICloneable" ascii //weight: 1
        $x_1_6 = "get_White" ascii //weight: 1
        $x_1_7 = "GetDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AD_2147781868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AD!MTB"
        threat_id = "2147781868"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WebClient" ascii //weight: 1
        $x_1_2 = "GetProcessesByName" ascii //weight: 1
        $x_1_3 = "GetTempPath" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "WriteAllBytes" ascii //weight: 1
        $x_1_6 = "Kill" ascii //weight: 1
        $x_1_7 = "metalshoopp.000webhostapp.com/WindowsFormsApp11.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AA_2147784196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AA!MTB"
        threat_id = "2147784196"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Pacman_Eating_Cherry" ascii //weight: 1
        $x_1_2 = "EventRegistration" ascii //weight: 1
        $x_1_3 = {02 28 15 00 00 0a 00 00 28 16 00 00 0a 02 05 28 09 00 00 06 6f 17 00 00 0a 0a 06 72 ?? 00 00 70 6f 18 00 00 0a 0b 07 72 ?? 00 00 70 20 00 01 00 00 14 14 19 8d 57 00 00 01 25 16 28 05 00 00 06 a2 25 17 28 06 00 00 06 a2 25 18 72 ?? 00 00 70 a2 0c 08 6f 19 00 00 0a 26 2a}  //weight: 1, accuracy: Low
        $x_1_4 = {00 03 17 8d 5a 00 00 01 25 16 1f 20 9d 6f 1a 00 00 0a 7e 4d 01 00 04 25 2d 17 26 7e 4c 01 00 04 fe 06 7f 01 00 06 73 1b 00 00 0a 25 80 4d 01 00 04 28 01 00 00 2b 28 02 00 00 2b 0a 06 0b 2b 00 07 2a}  //weight: 1, accuracy: High
        $x_1_5 = "C:\\Users\\tataki\\Source\\Repos\\Pacman" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_SIBA_2147794730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.SIBA!MTB"
        threat_id = "2147794730"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 0b 72 ?? ?? ?? ?? 0c 00 2b ?? [0-6] 08 13 ?? 16 13 ?? 2b 34 11 03 11 04 6f ?? ?? ?? ?? 13 ?? 00 12 ?? 28 ?? ?? ?? ?? 13 ?? 07 17 58 0b 12 08 28 ?? ?? ?? ?? 13 ?? 06 11 0e 11 0b 6f ?? ?? ?? ?? 0a 00 11 04 17 58 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KA_2147796993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KA!MTB"
        threat_id = "2147796993"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 11 04 11 07 11 09 58 17 58 17 59 11 08 11 0a 58 17 58 17 59 6f ?? 00 00 0a 13 0b 12 0b 28 ?? 00 00 0a 13 0c 09 08 11 0c 9c 08 17 58 0c 11 0a 17 58 13 0a 00 11 0a 17 fe 04 13 0d 11 0d 2d c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_LSH_2147807344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.LSH!MTB"
        threat_id = "2147807344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 09 16 0c 2b 61 09 07 08 6f ?? ?? ?? 0a 13 04 11 04 16 16 16 16 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 0a 11 0a 2c 3d 06 12 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 12 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 11 04 8c ?? ?? ?? 01 20 ?? ?? ?? f0 28 ?? ?? ?? 06 18 14 28 ?? ?? ?? 0a a5 09 00 00 01 6f ?? ?? ?? 0a 08 17 d6 0c 08 11 09 fe 02 16 fe 01 13 0b 11 0b 2d 91}  //weight: 1, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RPM_2147811604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RPM!MTB"
        threat_id = "2147811604"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "18.159.59.253" wide //weight: 1
        $x_1_2 = "Loogfrcy.log" wide //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "DipmDowDipmnlDipmoadDDipmataDipm" wide //weight: 1
        $x_1_5 = "-enc WwBUAGgAcgBlAGEA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RPO_2147811606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RPO!MTB"
        threat_id = "2147811606"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WjcqDowWjcqnlWjcqoadDWjcqataWjcq" wide //weight: 1
        $x_1_2 = "20.51.217.113" wide //weight: 1
        $x_1_3 = "Feeut.log" wide //weight: 1
        $x_1_4 = "powershell" wide //weight: 1
        $x_1_5 = "Dmitmzunvrinzjpygdmeiobm" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RPB_2147812379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RPB!MTB"
        threat_id = "2147812379"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "i.uguu.se" wide //weight: 1
        $x_1_2 = "WfyZvXQb.rtf" wide //weight: 1
        $x_1_3 = "fixedhost.modulation" wide //weight: 1
        $x_1_4 = "trading" wide //weight: 1
        $x_1_5 = "Bangv4.pdb" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "DownloadString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RPD_2147812381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RPD!MTB"
        threat_id = "2147812381"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "transfer.sh" wide //weight: 1
        $x_1_2 = "bin.txt" wide //weight: 1
        $x_1_3 = "Aspnet_compiler.exe" wide //weight: 1
        $x_1_4 = "Skidomoney.Money" wide //weight: 1
        $x_1_5 = "vv.txt" wide //weight: 1
        $x_1_6 = "NBCBCXNBNCBNCBMBNCXNCXNCNXBCNBX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RPE_2147812382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RPE!MTB"
        threat_id = "2147812382"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "transfer.sh" wide //weight: 1
        $x_1_2 = "binchris.txt" wide //weight: 1
        $x_1_3 = "Aspnet_compiler.exe" wide //weight: 1
        $x_1_4 = "Skidomoney.Money" wide //weight: 1
        $x_1_5 = "D.txt" wide //weight: 1
        $x_1_6 = "NBCBCXNBNCBNCBMBNCXNCXNCNXBCNBX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_LKIN_2147813200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.LKIN!MTB"
        threat_id = "2147813200"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {07 1a 5a 09 58 08 09 91 9c 00 09 17 58 0d 09 08 8e 69 fe 04 13 04 11 04 2d e0 00 07 17 58 0b 07 06 8e 69 fe 04 13 05 11 05 2d c1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MKIN_2147813201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MKIN!MTB"
        threat_id = "2147813201"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 05 00 00 0a 0a 73 06 00 00 0a 0b 06 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 00 00 06 16 6f ?? ?? ?? 0a 0c 16 0d 38 14 00 00 00 08 09 91 13 04 00 07 11 04 6f ?? ?? ?? 0a 00 00 09 17 58 0d 09 08 8e 69 3f e3 ff ff ff 07 6f ?? ?? ?? 0a 00 07 13 05 38 00 00 00 00 11 05 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MD_2147814240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MD!MTB"
        threat_id = "2147814240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 06 07 11 06 28 ?? ?? ?? 0a 0b 00 09 17 d6 0d 09 08 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d b8 07 0a 2b 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "Z___________________" ascii //weight: 1
        $x_1_5 = "Create__Instance__" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MC_2147814545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MC!MTB"
        threat_id = "2147814545"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-enc YwBtAGQAIAAvAGMAIAB0AGkAbQBlAG8AdQB0ACAAMgAwAA==" wide //weight: 1
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = "ToArray" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "FromString" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RPA_2147814666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RPA!MTB"
        threat_id = "2147814666"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdn.discordapp.com" wide //weight: 1
        $x_1_2 = "Mwzavc.jpg" wide //weight: 1
        $x_1_3 = "Gnywxifyndasrqomakli" wide //weight: 1
        $x_1_4 = "WebRequest" ascii //weight: 1
        $x_1_5 = "WriteLine" ascii //weight: 1
        $x_1_6 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RPF_2147814959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RPF!MTB"
        threat_id = "2147814959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdn.discordapp.com" wide //weight: 1
        $x_1_2 = "Aoykj_42180_.bmp" wide //weight: 1
        $x_1_3 = "Mtvngwyu" wide //weight: 1
        $x_1_4 = "powershell" wide //weight: 1
        $x_1_5 = "get_Assembly" ascii //weight: 1
        $x_1_6 = "Reverse" ascii //weight: 1
        $x_1_7 = "ReadBytes" ascii //weight: 1
        $x_1_8 = "WebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RPG_2147814960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RPG!MTB"
        threat_id = "2147814960"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 09 07 09 07 8e 69 5d 91 06 09 91 61 d2 9c 09 13 04 11 04 17 58 0d 09 06 8e 69 32 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RPG_2147814960_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RPG!MTB"
        threat_id = "2147814960"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdn.discordapp.com" wide //weight: 1
        $x_1_2 = "Jsgivzce.png" wide //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "enc YwBtAGQAIAAvAGMAIAB0AGkAbQBlAG8AdQB0ACAAMQA1AA" wide //weight: 1
        $x_1_5 = "Email Checker Pro" wide //weight: 1
        $x_1_6 = "Qgkktedezvnyzfmxmfdjxa" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RPH_2147815044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RPH!MTB"
        threat_id = "2147815044"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kmxdvwo" wide //weight: 1
        $x_1_2 = "Pyqaocuajm.Jornhwdpej" wide //weight: 1
        $x_1_3 = "Siparis onayi" ascii //weight: 1
        $x_1_4 = "Hrhiko" ascii //weight: 1
        $x_1_5 = "smethod_4" ascii //weight: 1
        $x_1_6 = "GZipStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RPH_2147815044_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RPH!MTB"
        threat_id = "2147815044"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 79 00 70 00 75 00 72 00 65 00 2e 00 30 00 30 00 30 00 77 00 65 00 62 00 68 00 6f 00 73 00 74 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 75 00 72 00 65 00 [0-64] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Google Update Setup" ascii //weight: 1
        $x_1_3 = "WebRequest" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "ReadBytes" ascii //weight: 1
        $x_1_6 = "DynamicInvoke" ascii //weight: 1
        $x_1_7 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_MSIL_Formbook_RPH_2147815044_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RPH!MTB"
        threat_id = "2147815044"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lvrjilegq.Fsjegcsowpyxshqdi" wide //weight: 1
        $x_1_2 = "Msmmdrvrcvbjsl" wide //weight: 1
        $x_1_3 = "185.222.58.56" wide //weight: 1
        $x_1_4 = "Ibzcbmng.png" wide //weight: 1
        $x_1_5 = "GetByteArrayAsync" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RPI_2147815045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RPI!MTB"
        threat_id = "2147815045"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "raphaellasia.com" wide //weight: 1
        $x_1_2 = "Kveujamr.bmp" wide //weight: 1
        $x_1_3 = "Nrvbpqvx" wide //weight: 1
        $x_1_4 = "get_Assembly" ascii //weight: 1
        $x_1_5 = "Stopwatch" ascii //weight: 1
        $x_1_6 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RPI_2147815045_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RPI!MTB"
        threat_id = "2147815045"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 00 69 00 76 00 65 00 72 00 67 00 65 00 6e 00 74 00 69 00 2e 00 74 00 65 00 63 00 68 00 2f 00 64 00 65 00 76 00 2f 00 [0-16] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = "ToArray" ascii //weight: 1
        $x_1_3 = "Write" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "ReadByte" ascii //weight: 1
        $x_1_6 = "Concat" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "GetType" ascii //weight: 1
        $x_1_9 = "Replace" ascii //weight: 1
        $x_1_10 = "GetResponseStream" ascii //weight: 1
        $x_1_11 = "Encoding" ascii //weight: 1
        $x_1_12 = "WebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_ME_2147815841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ME!MTB"
        threat_id = "2147815841"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 06 08 6f ?? ?? ?? 22 00 07 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a [0-10] 06 18 6f ?? ?? ?? 0a 00 02 0d 06 6f ?? ?? ?? 0a 09 16 09 8e 69 6f ?? ?? ?? 0a 13 04 de}  //weight: 1, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "Sleep" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "set_Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MI_2147816209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MI!MTB"
        threat_id = "2147816209"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "57"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {03 09 03 6f ?? ?? ?? 0a 5d 17 d6 28 ?? ?? ?? 0a da 13 04 07 11 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 09 17 d6 0d 09 08 31}  //weight: 30, accuracy: Low
        $x_5_2 = "FromBase64String" wide //weight: 5
        $x_5_3 = "I____________________" ascii //weight: 5
        $x_5_4 = "DebuggableAttribute" ascii //weight: 5
        $x_5_5 = "Create__Instance__" ascii //weight: 5
        $x_5_6 = "ToCharArray" wide //weight: 5
        $x_2_7 = "frmStory_KeyDown" ascii //weight: 2
        $x_2_8 = "MUHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHA" wide //weight: 2
        $x_2_9 = "InternetCheck" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 5 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_MJ_2147816620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MJ!MTB"
        threat_id = "2147816620"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 8e 69 8d ?? ?? ?? 01 0a 16 0b 2b 1c 00 06 07 02 07 91 03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d}  //weight: 5, accuracy: Low
        $x_1_2 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "ObfuscationAttribute" ascii //weight: 1
        $x_1_6 = ".compressed" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MP_2147817145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MP!MTB"
        threat_id = "2147817145"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 0b 16 0c 2b 16 07 08 91 0d [0-2] 7e ?? ?? ?? 04 09 6f ?? ?? ?? 0a [0-3] 08 17 58 0c 08 07 8e 69 32 e4 7e ?? ?? ?? 04 6f ?? ?? ?? 0a [0-2] 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "PingReply" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MM_2147817201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MM!MTB"
        threat_id = "2147817201"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_MKortz" ascii //weight: 1
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "@XAREam@xetalsi.@XAREdll" wide //weight: 1
        $x_1_4 = "==InvwZQ==oke" wide //weight: 1
        $x_1_5 = "UploadFile" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MO_2147817204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MO!MTB"
        threat_id = "2147817204"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 17 13 05 2b 35 07 11 05 17 da 6f ?? ?? ?? 0a 08 11 05 08 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a da 13 06 09 11 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0d 11 05 17 d6 13 05 11 05 11 04 31 c5 09 0a 2b 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "Create__Instance" ascii //weight: 1
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_FLL_2147817410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.FLL!MTB"
        threat_id = "2147817410"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GetPixel" ascii //weight: 2
        $x_2_2 = "ToArray" ascii //weight: 2
        $x_2_3 = "GetResponseStream" ascii //weight: 2
        $x_1_4 = "3.110.216.64" wide //weight: 1
        $x_1_5 = "tiny.one/4zurye9b" wide //weight: 1
        $x_1_6 = "2.58.149.219" wide //weight: 1
        $x_1_7 = "x.rune-spectrals.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Formbook_NUK_2147818657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NUK!MTB"
        threat_id = "2147818657"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShortPfafddddddddddddddddfdddrocess Completed" ascii //weight: 1
        $x_1_2 = "ShortPddddddfddddddddddfdddrocess Completed" ascii //weight: 1
        $x_1_3 = "ShortPddddddddddfmpleted" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "dasd Completed" ascii //weight: 1
        $x_1_6 = "faf Completed" ascii //weight: 1
        $x_1_7 = "dasdsfddleted" ascii //weight: 1
        $x_1_8 = "dafpleted" ascii //weight: 1
        $x_1_9 = "dfpleted" ascii //weight: 1
        $x_1_10 = "dasdsad Completed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_HLUF_2147818769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.HLUF!MTB"
        threat_id = "2147818769"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 16 f4 00 00 0c 2b 13 00 72 ?? ?? ?? 70 07 08 28 ?? ?? ?? 06 0b 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_QBFA_2147818770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.QBFA!MTB"
        threat_id = "2147818770"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 16 44 00 00 0c 2b 13 00 72 ?? ?? ?? 70 07 08 28 ?? ?? ?? 06 0b 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e2}  //weight: 1, accuracy: Low
        $x_1_2 = "Voroni" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NUM_2147819028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NUM!MTB"
        threat_id = "2147819028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BeginRead" ascii //weight: 1
        $x_1_2 = "@System@.@Reflection@.@Assembly@" ascii //weight: 1
        $x_1_3 = "@@@Load@@@" ascii //weight: 1
        $x_1_4 = "WA1.Resources" ascii //weight: 1
        $x_1_5 = "AsSsMmB" ascii //weight: 1
        $x_1_6 = "GetManifestResourceNames" ascii //weight: 1
        $x_1_7 = "Invoke" ascii //weight: 1
        $x_1_8 = "VS_VERSION_INFO" ascii //weight: 1
        $x_1_9 = "VarFileInfo" ascii //weight: 1
        $x_1_10 = "StringFileInfo" ascii //weight: 1
        $x_1_11 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RPP_2147819097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RPP!MTB"
        threat_id = "2147819097"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 03 02 4b 03 04 5f 03 66 05 5f 60 58 0e 07 0e 04 e0 95 58 7e c7 00 00 04 0e 06 17 59 e0 95 58 0e 05 28 bd 02 00 06 58 54 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NUW_2147819399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NUW!MTB"
        threat_id = "2147819399"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 04 17 58 7e ?? ?? ?? 04 5d 91 0a 03 04 28 ?? ?? ?? 06 06 59 05 58 05 5d 0b 03 04 7e ?? ?? ?? 04 5d 07 d2 9c 03 0c 2b [0-1] 08 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {04 5d 91 0a 06 7e ?? ?? ?? 04 03 1f 16 5d 6f ?? ?? ?? 0a 61 0b 2b 00 07 2a}  //weight: 1, accuracy: Low
        $x_1_3 = {06 0b 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NUX_2147819559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NUX!MTB"
        threat_id = "2147819559"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 bf b6 3d 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 fc 00 00 00 41 00 00 00 30 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "$ab287205-2cce-4d56-9b6f-b06ce28a31d7" ascii //weight: 1
        $x_1_3 = "TimeUtils.Properties" wide //weight: 1
        $x_1_4 = "GetDelegateForFunctionPointer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NVD_2147820220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NVD!MTB"
        threat_id = "2147820220"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 13 08 11 08 2c 10 00 06 11 07 6f ?? ?? ?? 06 28 ?? ?? ?? 0a 0a 00 11 06 6f ?? ?? ?? 06 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 13 09 11 09 2c 10 00 06 11 07 6f ?? ?? ?? 06 28 ?? ?? ?? 0a 0a 00 11 06 6f ?? ?? ?? 06 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 13 0a 11 0a 2c 10 00 06 11 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NVD_2147820220_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NVD!MTB"
        threat_id = "2147820220"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 23 00 00 70 28 53 00 00 0a 0b 07 72 27 00 00 70 28 53 00 00 0a 0b 07 72 2b 00 00 70 28 53 00 00 0a 0b 07 72 17 00 00 70 28 53 00 00 0a 0b 07 72 2f 00 00 70 28 53 00 00 0a 0b 07 72 13 00 00 70 28 53 00 00 0a 0b 07 72 0f 00 00 70 28 53 00 00 0a 0b 07 72 33 00 00 70 28 53 00 00 0a 0b 07 72 37 00 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NVG_2147820222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NVG!MTB"
        threat_id = "2147820222"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 04 2b 00 02 03 17 58 7e ?? ?? ?? 04 5d 91 0a 16 0b 16 13 05 2b 00 02 03 1f 16 28 ?? ?? ?? 06 0c 06 04 58 0d 08 09 59 04 5d 0b 16 13 06 2b 00 02 03 7e ?? ?? ?? 04 5d 07 28}  //weight: 1, accuracy: Low
        $x_1_2 = "System.Reflection.Assembly" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NV_2147820223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NV!MTB"
        threat_id = "2147820223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 bd a2 3d 09 07 00 00 00 00 00 00 00 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = "SG40FFZ584HXG5GTE555PW" wide //weight: 1
        $x_1_3 = "System.Reflection.Assembly" wide //weight: 1
        $x_1_4 = "$240a5f33-9cca-469f-a591-3560338f8b34" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_ND_2147821108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ND!MTB"
        threat_id = "2147821108"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 0b 91 61 07 11 09 91 11 06 58 11 06 5d 59 d2 9c 00 11 05 17 58 13 05 11 05}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_ND_2147821108_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ND!MTB"
        threat_id = "2147821108"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 55 a2 cb 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 9f 00 00 00 13 00 00 00 4c 00 00 00 b0 00 00 00 5e 00 00 00 2b 01 00 00 34 01 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = "a459-13c30d30aa07" ascii //weight: 1
        $x_1_3 = "SQLAppLogin.Resources.resource" ascii //weight: 1
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NTW_2147822311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NTW!MTB"
        threat_id = "2147822311"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 15 b6 09 09 01 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 62 00 00 00 0d 00 00 00 20 00 00 00 55 00 00 00 35 00 00 00 9d 00 00 00 30}  //weight: 1, accuracy: High
        $x_1_2 = {57 15 a2 09 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 3a 00 00 00 0b 00 00 00 0c 00 00 00 24 00 00 00 08 00 00 00 4a 00 00 00 53 00 00 00 19}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Formbook_NW_2147822312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NW!MTB"
        threat_id = "2147822312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "94e692d4-e964-484d-891b-b94c06f65522" ascii //weight: 5
        $x_1_2 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_3 = "set_PasswordChar" ascii //weight: 1
        $x_1_4 = "get_Password" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NW_2147822312_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NW!MTB"
        threat_id = "2147822312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 97 a2 2b 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 81 00 00 00 31 00 00 00 d2 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "PacMan.Properties.Resources.resource" ascii //weight: 1
        $x_1_3 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 1
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NE_2147822942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NE!MTB"
        threat_id = "2147822942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 8e 69 5d 91 9c 00 11 04 17 58}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NE_2147822942_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NE!MTB"
        threat_id = "2147822942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 11 0d 16 11 0b 6f 4c 00 00 0a 26 11 0a 11 0d 16 11 0b 11 0c 16 6f 56 00 00 0a 13 0f 7e 0e 00 00 04 11 0c 16 11 0f 6f 57 00 00 0a 11 0e 11 0b 58 13 0e 11 0e 11 0b 58 6a 06 6f 4f 00 00 0a 25 26 32 bd}  //weight: 1, accuracy: High
        $x_1_2 = "S0xKREtKTERTSkpTRCQ=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NYE_2147826305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NYE!MTB"
        threat_id = "2147826305"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Tefsdddddmp" ascii //weight: 1
        $x_1_2 = "C:\\NeddddddddddddddddddddddwTemp" ascii //weight: 1
        $x_1_3 = "lpBfdsdhhfsdsdsffuffer" ascii //weight: 1
        $x_1_4 = "fffffffdhsdhsdhshdfhfsdffffff" ascii //weight: 1
        $x_1_5 = "ssfsfddshfasff" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NYF_2147826834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NYF!MTB"
        threat_id = "2147826834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 d4 02 fc c9 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 ?? 00 00 00 16 00 00 00 57 00 00 00 74 00 00 00 ?? 00 00 00 ?? 00 00 00 01 00 00 00 03 00 00 00 17 00 00 00 01 00 00 00 02 00 00 00 02 00 00 00 02 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NZ_2147827604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NZ!MTB"
        threat_id = "2147827604"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 15 a2 09 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 83 00 00 00 10 00 00 00 32 01 00 00 f6 02 00 00 4f}  //weight: 1, accuracy: High
        $x_1_2 = {02 00 00 d6 00 00 00 90 05 00 00 36 00 00 00 0c 00 00 00 22 01 00 00 3b 02 00 00 0a 00 00 00 01 00 00 00 06 00 00 00 08 00 00 00 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NZ_2147827604_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NZ!MTB"
        threat_id = "2147827604"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0b 11 07 61 13 0c 11 0c 11 09 59}  //weight: 2, accuracy: High
        $x_1_2 = "19031102-5ad0-4ed5-8ea1-12ff1a08ce7d" ascii //weight: 1
        $x_1_3 = "set_UseShellExecute" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NEA_2147827667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NEA!MTB"
        threat_id = "2147827667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pTHSLxkMBDrJPNdYoCaHCGFqZiLEAbyKMQPjmDXEtNcZQBGwgXJARzTeFsRSYWfnWKKtRKWkbPRCFefBHTrHM" wide //weight: 1
        $x_1_2 = "WScript.Shell" wide //weight: 1
        $x_1_3 = "powershell.exe" wide //weight: 1
        $x_1_4 = "-WindowStyle Hidden Start-Sleep 5" wide //weight: 1
        $x_1_5 = "RegAsm.exe" wide //weight: 1
        $x_1_6 = "Application.lnk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PFA_2147827833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PFA!MTB"
        threat_id = "2147827833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 16 0c 02 00 0b [0-6] 06 07 20 00 01 00 00 28 ?? ?? ?? 06 0a 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 [0-23] 74 ?? ?? ?? 01 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 80 ?? ?? ?? 04 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 06 72 55 16 00 70 20 00 01 00 00 14 14 17 8d ?? ?? ?? 01 25 16 02 a2 6f ?? ?? ?? 0a 0b 2b 00 07 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Formbook_PFC_2147827834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PFC!MTB"
        threat_id = "2147827834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 af 1b 00 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 0a 20 ?? ?? ?? 00 0b 2b 35 20 ?? ?? ?? ca 20 ?? ?? ?? e3 61 25 0d 1d 5e 45 07 00 00 00 21 00 00 00 05 00 00 00 34 00 00 00 d0 ff ff ff 51 00 00 00 85 00 00 00 5c 00 00 00 38 ?? ?? ?? 00 07 16 fe 04 16 fe 01 0c 08 2d 08 20 ?? ?? ?? ed 25 2b 06 20 ?? ?? ?? ca 25 26 2b b4 07 15 58 0b 09 20 ?? ?? ?? 5c 5a 20 ?? ?? ?? cf 61 2b a1 06 07 20 00 01 00 00 28 ?? ?? ?? 06 0a 00 09 20 ?? ?? ?? 0c 5a 20 ?? ?? ?? e7 61 2b 84 00 20 ?? ?? ?? f2 38 ?? ?? ?? ff 06 28 ?? ?? ?? 06 74 ?? ?? ?? 01 6f ?? ?? ?? 0a 17 9a 80 ?? ?? ?? 04 09 20 ?? ?? ?? e9 5a 20 ?? ?? ?? c9 61 38 ?? ?? ?? ff 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 3b 06 72 ?? ?? ?? 70 20 00 01 00 00 14 14 17 8d ?? ?? ?? 01 25 16 02 a2 6f ?? ?? ?? 0a 0b 08 20 ?? ?? ?? 1a 5a 20 ?? ?? ?? 49 61 2b b3 08 20 ?? ?? ?? 25 5a 20 ?? ?? ?? 87 61 2b a4 07 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RPU_2147828537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RPU!MTB"
        threat_id = "2147828537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 31 00 34 00 32 00 2f 00 [0-48] 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {09 08 11 04 08 8e 69 5d 91 06 11 04 91 61 d2 6f ?? 00 00 0a 11 04 17 58 13 04 11 04 06 8e 69 32 df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RPV_2147828538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RPV!MTB"
        threat_id = "2147828538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 00 39 00 38 00 2e 00 34 00 36 00 2e 00 31 00 33 00 32 00 2e 00 31 00 37 00 38 00 2f 00 [0-48] 2e 00 62 00 6d 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
        $x_1_6 = "CreateDelegate" ascii //weight: 1
        $x_1_7 = "WriteLine" ascii //weight: 1
        $x_1_8 = "GetInvocationList" ascii //weight: 1
        $x_1_9 = "DynamicInvoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NEC_2147828741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NEC!MTB"
        threat_id = "2147828741"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$d99076c0-458e-41a2-a8ac-0842e090c7d1" ascii //weight: 1
        $x_1_2 = "Cssquxhb_Eewzaemy.png" wide //weight: 1
        $x_1_3 = "Eksnmgwfdvgsflrblurjm" wide //weight: 1
        $x_1_4 = "992302676874375178" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NED_2147828742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NED!MTB"
        threat_id = "2147828742"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Q2hlY2tSZW1vdGVEZWJ1Z2dlclByZXNlbnQ=" wide //weight: 1
        $x_1_2 = "VmlydHVhbFByb3RlY3Q=" wide //weight: 1
        $x_1_3 = "TG9hZExpYnJhcnlB" wide //weight: 1
        $x_1_4 = "a2VybmVsMzI=" wide //weight: 1
        $x_1_5 = "R2V0RW52aXJvbm1lbnRWYXJpYWJsZQ==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NXW_2147830738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NXW!MTB"
        threat_id = "2147830738"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Directory you wagdgggggggnt to delete is not exist" ascii //weight: 1
        $x_1_2 = "FaissdlfhdcdasssssssdssfssssdsssssdsssssssssassdgggggggggggddgdsddddddfddgggfsfgfgUpdate" ascii //weight: 1
        $x_1_3 = "chffkafsshdghf" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NXW_2147830738_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NXW!MTB"
        threat_id = "2147830738"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 00 72 00 65 00 73 00 00 09 6f 00 75 00 72 00 63 00 00 05 65 00 73 00 00 0d 78 00 63 00 76 00 74 00 68 00 36 00 00 09 76}  //weight: 1, accuracy: High
        $x_1_2 = "mjhm67i" ascii //weight: 1
        $x_1_3 = "xcvth6" ascii //weight: 1
        $x_1_4 = "GetManifestResourceNames" ascii //weight: 1
        $x_1_5 = "YYYSYYYyYYYsYYYtYYYeYYYmYYY" ascii //weight: 1
        $x_1_6 = "YYYRYYYeYYYfYYYlYYYeYYYcYYYtYYYiYYYoYYYnYYY" ascii //weight: 1
        $x_1_7 = "YYYAYYYsYYYsYYYeYYYmYYYbYYYlYYYyYYY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NFN_2147831831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NFN!MTB"
        threat_id = "2147831831"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 09 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 07 06 28 ?? ?? ?? 06 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d c5}  //weight: 1, accuracy: Low
        $x_1_2 = "GetPixel" ascii //weight: 1
        $x_1_3 = "R0535" ascii //weight: 1
        $x_1_4 = "ColorTranslator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NFN_2147831831_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NFN!MTB"
        threat_id = "2147831831"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "uhbujiujhninhjikiuh" ascii //weight: 2
        $x_2_2 = "OSMetadata.HashElement" ascii //weight: 2
        $x_2_3 = "rewjngfgrfqe" ascii //weight: 2
        $x_2_4 = "okmnjiuhbv" ascii //weight: 2
        $x_1_5 = "GetPixel" ascii //weight: 1
        $x_1_6 = "ToWin32" ascii //weight: 1
        $x_1_7 = "ColorTranslator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NFN_2147831831_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NFN!MTB"
        threat_id = "2147831831"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OSMetadata.HashElement" wide //weight: 1
        $x_1_2 = "R3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrkto" ascii //weight: 1
        $x_1_3 = ".g.resource" ascii //weight: 1
        $x_1_4 = "GetPixel" ascii //weight: 1
        $x_1_5 = "ToWin32" ascii //weight: 1
        $x_1_6 = "ColorTranslator" ascii //weight: 1
        $x_1_7 = "GetType" ascii //weight: 1
        $x_1_8 = "Split" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RD_2147831856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RD!MTB"
        threat_id = "2147831856"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 7e 0c 00 00 04 73 57 00 00 0a 72 ?? ?? ?? ?? 6f 58 00 00 0a 74 03 00 00 1b 0a 73 59 00 00 0a 0b 73 5a 00 00 0a 0c 14 0d 1e 8d 57 00 00 01 13 04 08 1b 8d 57 00 00 01 25 d0 ?? ?? ?? ?? 28 5b 00 00 0a 6f 5c 00 00 0a 13 05 11 05 16 11 04 16 1e 28 5d 00 00 0a 00 07 11 04 6f 5e 00 00 0a 00 07 18 6f 5f 00 00 0a 00 07 6f 60 00 00 0a 13 06 11 06 06 16 06 8e 69 6f 61 00 00 0a 0d 09 28 14 00 00 06 28 13 00 00 06 72 ?? ?? ?? ?? 6f 62 00 00 0a 80 0b 00 00 04}  //weight: 2, accuracy: Low
        $x_2_2 = "sk41Ua2AFu5PANMKit.abiJPmfBfTL6iLfmaW" wide //weight: 2
        $x_1_3 = "Kulibing" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NWF_2147832447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NWF!MTB"
        threat_id = "2147832447"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 09 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 13 05 07 06 11 05 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 06 11 06 2d cc}  //weight: 1, accuracy: Low
        $x_1_2 = "rewjngfgrfqe" ascii //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
        $x_1_4 = "W2352535345" ascii //weight: 1
        $x_1_5 = "ColorTranslator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDB_2147832519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDB!MTB"
        threat_id = "2147832519"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Y5tFvU8EY" wide //weight: 1
        $x_2_2 = {00 16 13 04 2b 31 00 08 09 11 04 6f 95 01 00 0a 13 05 08 09 11 04 6f 95 01 00 0a 13 06 11 06 28 96 01 00 0a 13 07 07 06 11 07 28 97 01 00 0a 9c 00 11 04 17 58 13 04 11 04 08 6f 98 01 00 0a fe 04 13 08 11 08 2d bf 06 17 58 0a 00 09 17 58 0d 09 08 6f 99 01 00 0a fe 04 13 09 11 09 2d a1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDC_2147833126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDC!MTB"
        threat_id = "2147833126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 16 13 04 2b 32 00 08 09 11 04 28 ?? ?? ?? ?? 13 05 08 09 11 04 6f 6e 00 00 0a 13 06 11 06 28 6f 00 00 0a 13 07 17 13 08 00 07 06 11 07 d2 9c 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 09 11 09}  //weight: 2, accuracy: Low
        $x_2_2 = {07 28 70 00 00 0a 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 6f 71 00 00 0a 80 ?? ?? ?? ?? 02 13 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NEAA_2147834122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NEAA!MTB"
        threat_id = "2147834122"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$b89e408c-6865-4800-8688-027f9cf4cadb" ascii //weight: 5
        $x_5_2 = "aR3nbf8dQp2feLmk31" ascii //weight: 5
        $x_5_3 = "umLocehuEC" ascii //weight: 5
        $x_5_4 = "KDikMXewCI" ascii //weight: 5
        $x_2_5 = "$$method0x6000395-1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NJS_2147834357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NJS!MTB"
        threat_id = "2147834357"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$207bf3f8-34f4-408a-abec-0abca306b65a" ascii //weight: 10
        $x_1_2 = "DESCryptoServiceProvider" ascii //weight: 1
        $x_1_3 = "Kulibing" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "MatikkaPeli.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NWU_2147835151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NWU!MTB"
        threat_id = "2147835151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "P53YSCYRBVHHUP8G47B75Y" ascii //weight: 10
        $x_1_2 = "System.Reflection.Assembly" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NWV_2147835579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NWV!MTB"
        threat_id = "2147835579"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 25 0b 19 5e 45 03 00 00 00 11 00 00 00 02 00 00 00 e0 ff ff ff 2b 0f 07}  //weight: 1, accuracy: High
        $x_1_2 = "$13d44a0d-107c-473e-92f3-050b1678a80c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NYB_2147835582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NYB!MTB"
        threat_id = "2147835582"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5a 1e 58 6a 58 6f ?? ?? ?? 0a 05 6f ?? ?? ?? 0a 0b 05 6f ?? ?? ?? 0a 0c 05 6f ?? ?? ?? 0a 26 05 6f ?? ?? ?? 0a 0d 08 02 42 ?? ?? ?? 00 02 08 07 58}  //weight: 1, accuracy: Low
        $x_1_2 = "83-cb2b31a8c317" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NZB_2147836036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NZB!MTB"
        threat_id = "2147836036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {00 06 18 d8 0a 06 07 fe 02 13 05 11 05 2c 02 07 0a 00 06 07 5d 16}  //weight: 3, accuracy: High
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "WebServices" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NZB_2147836036_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NZB!MTB"
        threat_id = "2147836036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {25 16 1f 25 9d 6f ?? 00 00 0a 13 04 38 ?? ?? ?? ?? 00 02}  //weight: 3, accuracy: Low
        $x_1_2 = "Management_System.Properties.Resource" ascii //weight: 1
        $x_1_3 = "39905fc75b33" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NZB_2147836036_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NZB!MTB"
        threat_id = "2147836036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {04 8e 69 5d 93 03 61 d2 2a}  //weight: 1, accuracy: High
        $x_1_2 = "BLYAT LBLYAT oaBLYAT dBLYAT" wide //weight: 1
        $x_1_3 = "BLYAT GBLYAT eBLYAT tBLYAT TBLYAT yBLYAT pBLYAT e" wide //weight: 1
        $x_1_4 = "BLYAT EnBLYAT trBLYAT yPBLYAT oiBLYAT ntBLYAT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NEAB_2147836094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NEAB!MTB"
        threat_id = "2147836094"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 00 0a 0b 07 7e ?? 00 00 04 20 01 00 00 00 97 29 ?? 00 00 11 6f ?? 00 00 0a 16 8c ?? 00 00 01 14 6f ?? 00 00 0a 26 2a}  //weight: 5, accuracy: Low
        $x_2_2 = "M0r4p5mxZ0r4p5mx" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RS_2147836439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RS!MTB"
        threat_id = "2147836439"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 04 06 09 06 09 8e 69 5d 91 08 06 91 61 d2 9c 06 17 58 0a 06 08 8e 69 32 e6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RS_2147836439_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RS!MTB"
        threat_id = "2147836439"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 0b 00 00 06 0b 28 3f 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f 42 00 00 0a 11 04 17 58 13 04 11 04 07 8e 69 32 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RS_2147836439_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RS!MTB"
        threat_id = "2147836439"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 90 00 00 0a 28 8d 00 00 0a 16 16 11 09 11 08 18 28 99 00 00 06 28 8d 00 00 0a 18 28 99 00 00 06 28 91 00 00 0a 8c 59 00 00 01 a2 14 28 92 00 00 0a 1e}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RS_2147836439_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RS!MTB"
        threat_id = "2147836439"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 07 08 09 28 34 00 00 06 28 32 00 00 06 00 28 31 00 00 06 28 33 00 00 06 28 30 00 00 06 00 17 13 04 00 28 2f 00 00 06 d2 06 28 2d 00 00 06 00 00 00 09 17 58 0d 09 17 fe 04 13 05 11 05 2d c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDE_2147837542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDE!MTB"
        threat_id = "2147837542"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "f246ea5a-a018-4623-9bbe-4e235b9aa1d0" ascii //weight: 1
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "FlushFinalBlock" ascii //weight: 1
        $x_1_5 = "BHhHUiu" ascii //weight: 1
        $x_1_6 = "CryptoObfuscator_Output" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDF_2147838458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDF!MTB"
        threat_id = "2147838458"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 06 07 8e 69 5d 07 11 06 07 8e 69 5d 91 08 11 06 1f ?? 5d 91 61 28 ?? ?? ?? ?? 07 11 06 17 58 07 8e 69 5d 91 28 ?? ?? ?? ?? 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c}  //weight: 2, accuracy: Low
        $x_1_2 = "MonteCarloCards" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_SJN_2147839348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.SJN!MTB"
        threat_id = "2147839348"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 44 00 00 0a 72 a5 03 00 70 72 a9 03 00 70 6f 45 00 00 0a 72 b1 03 00 70 72 b5 03 00 70 6f 45 00 00 0a 72 b9 03 00 70 72 bd 03 00 70 6f 45 00 00 0a 0b 07 72 c1 03 00 70 18 17 8d 10 00 00 01 25 16 72 bd 03 00 70 a2}  //weight: 1, accuracy: High
        $x_1_2 = {28 48 00 00 0a d2 6f 49 00 00 0a 00 11 08 17 58 13 08 11 08 08 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDG_2147839569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDG!MTB"
        threat_id = "2147839569"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "016d1d6a-331e-4828-ba14-2a1656b1ad78" ascii //weight: 1
        $x_1_2 = "DHFHDFHDHHDF" ascii //weight: 1
        $x_2_3 = {09 11 0b 8f 2e 00 00 01 25 4b 11 0c 61 54 11 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NEAF_2147839974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NEAF!MTB"
        threat_id = "2147839974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 7b 94 00 00 04 7b f2 00 00 04 7e eb 00 00 04 20 0a 01 00 00 7e eb 00 00 04 20 0a 01 00 00 91 7e 48 00 00 04 20 b5 01 00 00 94 61 20 da 00 00 00 5f 9c 2a}  //weight: 10, accuracy: High
        $x_2_2 = "b.R.resources" ascii //weight: 2
        $x_2_3 = "154a1e24f234f6.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AZ_2147839986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AZ!MTB"
        threat_id = "2147839986"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HYTGKMn.pdb" ascii //weight: 2
        $x_2_2 = "HYTGKMn.Properties" ascii //weight: 2
        $x_1_3 = "GetMethod" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AZ_2147839986_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AZ!MTB"
        threat_id = "2147839986"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {95 58 20 ff 00 00 00 5f 13 18 09 11 17 07 11 17 91 11 04 11 18 95 61 28 ?? 00 00 0a 9c 00 11 17 17 58 13 17 11 17 09 8e 69 fe 04}  //weight: 4, accuracy: Low
        $x_1_2 = "48FW7C48EFBH58C9ZF5714" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AOK_2147841229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AOK!MTB"
        threat_id = "2147841229"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 1c 12 10 28 ?? ?? ?? 0a 0d 2b 12 12 10 28 ?? ?? ?? 0a 0d 2b 08 12 10 28 ?? ?? ?? 0a 0d 11 05 09 6f ?? ?? ?? 0a 08 17 58 0c 08 11 07 fe 04 13 0c 11 0c 2d a4 07 17 58 0b 07 11 08 fe 04 13 0d 11 0d 2d 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AOK_2147841229_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AOK!MTB"
        threat_id = "2147841229"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 16 0b 2b 13 00 06 07 06 07 91 ?? ?? ?? ?? ?? 59 d2 9c 07 17 58 0b 00 07 06 8e 69 fe 01 16 fe 01 0c 08}  //weight: 2, accuracy: Low
        $x_1_2 = "qataris.agency/423" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AOK_2147841229_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AOK!MTB"
        threat_id = "2147841229"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0a 2b 11 00 02 03 06 04 05 28 ?? 00 00 06 00 06 17 58 0a 00 06 02 6f ?? 00 00 0a 2f 0b 04 6f ?? 00 00 0a 05 fe 04 2b 01 16 0b 07 2d d6}  //weight: 2, accuracy: Low
        $x_1_2 = {02 03 04 6f ?? 00 00 0a 0a 0e 04 05 6f ?? 00 00 0a 59 0b 06 07 05 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AOK_2147841229_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AOK!MTB"
        threat_id = "2147841229"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 0a 06 72 ed 05 00 70 28 10 00 00 06 6f 40 00 00 0a 00 06 18 6f 41 00 00 0a 00 06 18 6f 42 00 00 0a 00 06 6f 43 00 00 0a 0b 07 02 16 02 8e 69 6f 44 00 00 0a 0c 2b 00}  //weight: 2, accuracy: High
        $x_1_2 = "formulario151122.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NEAG_2147841518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NEAG!MTB"
        threat_id = "2147841518"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {25 16 1f 2d 9d 6f 75 00 00 0a 0b 07 8e 69 8d b4 00 00 01 0c 16 13 05 2b 16 08 11 05 07 11 05 9a 1f 10 28 76 00 00 0a d2 9c 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d dd}  //weight: 10, accuracy: High
        $x_5_2 = "System.Reflection.Assembly" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAB_2147841942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAB!MTB"
        threat_id = "2147841942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 06 8e 69 5d 13 04 07 09 6f ?? 00 00 0a 5d 13 08 06 11 04 91 13 09 09 11 08 6f ?? 00 00 0a 13 0a 02 06 07 28 ?? 00 00 06 13 0b 02 11 09 11 0a 11 0b 28 ?? 00 00 06 13 0c 06 11 04 02 11 0c 28 ?? 00 00 06 9c 07 17 59 0b 07 16 fe 04 16 fe 01 13 0d 11 0d 2d aa}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_SPA_2147842204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.SPA!MTB"
        threat_id = "2147842204"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 05 08 9a 28 ?? ?? ?? 06 a2 08 17 58 0c 08 05 8e 69 32 eb}  //weight: 2, accuracy: Low
        $x_2_2 = {72 a9 01 00 70 02 72 5f 00 00 70 17 8d 01 00 00 01 0d 09 16 07 8c 05 00 00 01 a2 09 28 ?? ?? ?? 06 0c 07 17 58 0b 72 75 01 00 70 06 72 c9 01 00 70 17 8d 01 00 00 01 13 04 11 04 16 08 a2 11 04 28 ?? ?? ?? 06 26 de b8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NEAI_2147844053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NEAI!MTB"
        threat_id = "2147844053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$8a16465c-5037-46e6-acc7-07e4bfbd5d8f" ascii //weight: 5
        $x_2_2 = "JHhGg762.pdb" ascii //weight: 2
        $x_2_3 = "Confuser.Core 1.6.0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AAS_2147845652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AAS!MTB"
        threat_id = "2147845652"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 5d 01 00 70 28 ?? ?? ?? 0a 0b 06 07 6f ?? ?? ?? 0a 0c 02 8e 69 8d ?? ?? ?? 01 0d 08 02 16 02 8e 69 09 16 6f ?? ?? ?? 0a 13 04 09 11 04}  //weight: 2, accuracy: Low
        $x_1_2 = "Part08c08pat08on" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MBDB_2147846975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MBDB!MTB"
        threat_id = "2147846975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 59 13 05 2b 17 00 08 07 11 05 6f ?? 00 00 0a 6f ?? 00 00 0a 26 00 11 05 17 59 13 05 11 05 16 fe 04 16 fe 01 13 06 11 06 2d db}  //weight: 1, accuracy: Low
        $x_1_2 = {57 00 65 00 65 00 6e 00 67 00 00 35 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 00 09 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AFN_2147846993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AFN!MTB"
        threat_id = "2147846993"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 07 2b 19 08 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 86 6f ?? ?? ?? 0a 00 11 07 17 d6 13 07 11 07 11 06 31 e1}  //weight: 2, accuracy: Low
        $x_1_2 = "ISAT" wide //weight: 1
        $x_1_3 = "QuanLyBanGiay.CCM" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MBCX_2147847212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MBCX!MTB"
        threat_id = "2147847212"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 00 63 00 5a 00 36 00 6c 00 4d 00 51 00 2b 00 5a 00 58 00 4a 00 33 00 52 00 6a 00 51 00 75 00 2f 00 34 00 42 00 65 00 56 00 56 00 6a 00 74 00 65 00 61 00 57 00 66 00 53 00 68 00 79 00 39 00 4d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_ADF_2147847272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ADF!MTB"
        threat_id = "2147847272"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 04 2b 34 16 13 05 2b 1f 07 11 04 11 05 6f ?? ?? ?? 0a 13 06 08 12 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 05 17 58 13 05 11 05 07 6f ?? ?? ?? 0a 32 d7 11 04 17 58 13 04 11 04 07}  //weight: 2, accuracy: Low
        $x_1_2 = "OPN1LW_v1._1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AKF_2147847542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AKF!MTB"
        threat_id = "2147847542"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 04 2b 16 07 11 04 06 11 04 19 5a 58 1f 18 5d 1f 0c 59 9e 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d dd}  //weight: 1, accuracy: High
        $x_2_2 = {0a 16 13 07 2b 1c 00 06 11 07 11 07 1f 11 5a 11 07 18 62 61 20 aa 00 00 00 60 9e 00 11 07 17 58 13 07 11 07 06 8e 69 fe 04 13 08 11 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AKF_2147847542_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AKF!MTB"
        threat_id = "2147847542"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6c 07 16 9a 16 99 5a a1 25 17 12 09 28 ?? 00 00 0a 6c 07 17 9a 17 99 5a a1 25 18 12 09 28 ?? 00 00 0a 6c 07 18 9a 18 99 5a a1 13 0a 19 8d ?? 00 00 01 25 16 11 0a 16 99 d2 9c 25 17 11 0a 17 99}  //weight: 2, accuracy: Low
        $x_1_2 = "HarvestPigmentSequence" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AKF_2147847542_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AKF!MTB"
        threat_id = "2147847542"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 06 2b 27 00 07 11 05 11 06 6f ?? ?? ?? 0a 13 07 08 12 07 28 ?? ?? ?? 0a 8c 5a 00 00 01 6f ?? ?? ?? 0a 26 00 11 06 17 58 13 06 11 06 07 6f ?? ?? ?? 0a fe 04 13 08 11 08 2d c9 00 11 05 17 58 13 05 11 05 07 6f ?? ?? ?? 0a fe 04 13 09 11 09 2d ac}  //weight: 2, accuracy: Low
        $x_1_2 = "SalesInventory" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AIW_2147847543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AIW!MTB"
        threat_id = "2147847543"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 07 2b 1f 07 11 06 11 07 6f ?? ?? ?? 0a 13 08 08 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 07 17 58 13 07 11 07 07 6f ?? ?? ?? 0a 32 d7 11 06}  //weight: 2, accuracy: Low
        $x_1_2 = "OPN1LW_v1._1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AIW_2147847543_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AIW!MTB"
        threat_id = "2147847543"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 11 06 08 8e 69 5d 08 11 06 08 8e 69 5d 91 09 11 06 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 08 11 06 17 58 08 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 06 15 58 13 06 11 06 16 fe 04 16 fe 01 13 07 11 07 2d ac}  //weight: 2, accuracy: Low
        $x_1_2 = "DoAnBaoCao" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AJK_2147847544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AJK!MTB"
        threat_id = "2147847544"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 2b 49 00 07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 08 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 07 09 17 58 07 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 0a d2 9c 09 15 58 0d 00 09 16 fe 04 16 fe 01 13 07 11 07 2d aa}  //weight: 2, accuracy: Low
        $x_1_2 = "CuaHangDT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AJK_2147847544_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AJK!MTB"
        threat_id = "2147847544"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 04 2b 28 00 08 09 11 04 6f ?? ?? ?? 0a 13 0b 12 0b 28 ?? ?? ?? 0a 13 0c 07 11 05 11 0c 9c 11 05 17 58 13 05 00 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a fe 04 13 0d 11 0d 2d c8 00 09 17 58 0d 09 08 6f ?? ?? ?? 0a fe 04 13 0e 11 0e 2d ae}  //weight: 2, accuracy: Low
        $x_1_2 = "obstacle_avoidance1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_ALK_2147847545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ALK!MTB"
        threat_id = "2147847545"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 04 2b 28 00 08 09 11 04 6f ?? ?? ?? 0a 13 0b 12 0b 28 ?? ?? ?? 0a 13 0c 07 11 05 11 0c 9c 11 05 17 58 13 05 00 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a fe 04 13 0d 11 0d 2d c8}  //weight: 2, accuracy: Low
        $x_1_2 = "QuanLyBanThuoc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_GIF_2147847869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.GIF!MTB"
        threat_id = "2147847869"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 72 07 a3 02 70 72 0b a3 02 70 6f ?? ?? ?? 0a 0c 06 08 72 11 a3 02 70 72 ed 02 00 70 6f ?? ?? ?? 0a 7d bf 00 00 04 16 06 7b bf 00 00 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 7e c1 00 00 04 25 2d 17 26 7e c0 00 00 04 fe 06 64 00 00 06 73 78 00 00 0a 25 80 c1 00 00 04 28 ?? ?? ?? 2b 06 fe 06 61 00 00 06 73 7a 00 00 0a 28 02 00 00 2b 28 03 00 00 2b 0d 28 ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 13 04 11 04 6f ?? ?? ?? 0a 16 9a 6f ?? ?? ?? 0a 18 9a 13 05 11 05 16 8c 3a 00 00 01 02 7b 0f 00 00 04 13 08 11 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AWM_2147847998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AWM!MTB"
        threat_id = "2147847998"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 04 2b 28 00 08 09 11 04 6f ?? ?? ?? 0a 13 0f 12 0f 28 ?? ?? ?? 0a 13 10 07 11 05 11 10 9c 11 05 17 58 13 05 00 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a fe 04 13 11 11 11 2d c8 00 09 17 58 0d 09 08 6f ?? ?? ?? 0a fe 04 13 12 11 12 2d ae}  //weight: 2, accuracy: Low
        $x_1_2 = "TuringMachineSimulation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MAAV_2147848529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MAAV!MTB"
        threat_id = "2147848529"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {37 00 45 00 79 00 66 00 35 00 49 00 4e 00 49 00 6e 00 61 00 62 00 72 00 44 00 46 00 68 00 48 00 45 00 2e 00 63 00 31 00 36 00 49 00 6b 00 30 00 32 00 4b 00 53 00 77 00 4c 00 6d 00 71 00 6f 00 42 00 46 00 44 00 79}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PSPF_2147848880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PSPF!MTB"
        threat_id = "2147848880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 72 18 1c 00 70 0a 06 72 56 1c 00 70 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 0b 07 0c 2b 00 08 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MBFC_2147850098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MBFC!MTB"
        threat_id = "2147850098"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pjqjipaeiasdpawaffeafa" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MBFR_2147850542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MBFR!MTB"
        threat_id = "2147850542"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 16 11 04 a2 25 17 7e ?? 00 00 0a a2 25 18 11 01 a2 25 19 17}  //weight: 1, accuracy: Low
        $x_1_2 = "79fa4dba-71fa-4780-a24c-b5493d2d61a0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDL_2147851865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDL!MTB"
        threat_id = "2147851865"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c7d60c2f-c6ba-4567-bf81-c5c05297412f" ascii //weight: 1
        $x_1_2 = "ProducerInvocationCollection" ascii //weight: 1
        $x_1_3 = "TJMwd" ascii //weight: 1
        $x_1_4 = "Tmavwtyheiz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PSUC_2147852362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PSUC!MTB"
        threat_id = "2147852362"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 02 28 07 00 00 0a 0a 28 08 00 00 0a 06 28 07 00 00 06 6f 09 00 00 0a 0b 2b 00 07 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AGM_2147852536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AGM!MTB"
        threat_id = "2147852536"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 36 00 07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 1f 16 5d 6f ?? ?? ?? 0a 61 07 09 17 58 07 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 09 15 58 0d 00 09 16 fe 04 16 fe 01 13 06 11 06 2d bd}  //weight: 2, accuracy: Low
        $x_1_2 = "Task1Simulation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AGCK_2147852540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AGCK!MTB"
        threat_id = "2147852540"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 1f 16 5d 6f ?? ?? ?? 0a 61 07 09 17 58 07 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 09 15 58 0d 00 09 16 fe 04 16 fe 01 13 06}  //weight: 2, accuracy: Low
        $x_1_2 = "OAnQuan" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MBID_2147888930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MBID!MTB"
        threat_id = "2147888930"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 11 04 02 11 04 91 07 61 06 09 91 61 28 ?? 00 00 0a 9c 09 06 8e 69 17 59 fe 01 13 05 11 05 2c 04}  //weight: 1, accuracy: Low
        $x_1_2 = {58 00 00 05 58 00 31 00 00 05 58 00 32 00 00 0f 4d 00 6f 00 64 00 75 00 6c 00 65 00 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PSWF_2147889172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PSWF!MTB"
        threat_id = "2147889172"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 00 6f 0c 00 00 0a 28 ?? 00 00 06 13 09 20 01 00 00 00 7e 5d 00 00 04 7b 63 00 00 04 3a b7 ff ff ff 26 20 01 00 00 00 38 ac ff ff ff 11 00 72 61 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 20 03 00 00 00 38 91 ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AGNM_2147889427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AGNM!MTB"
        threat_id = "2147889427"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1f 16 58 13 1b 2b 4e 00 11 1b 11 04 5d 13 1c 11 1b 11 05 5d 13 1d 08 11 1c 91 13 1e 09 11 1d 6f ?? ?? ?? 0a 13 1f 08 11 1b 17 58 11 04 5d 91 13 20 11 1e 11 1f 61 11 20 59 20 00 01 00 00 58 13 21 08 11 1c 11 21 20 00 01 00 00 5d d2 9c 00 11 1b 17 59 13 1b 11 1b 16 fe 04 16 fe 01 13 22 11 22 2d a4}  //weight: 2, accuracy: Low
        $x_1_2 = "QuanLyKhoBanhKeo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AJFM_2147889446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AJFM!MTB"
        threat_id = "2147889446"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 0a 2b 50 11 0a 11 14 5d 13 16 11 0a 11 18 5d 13 1b 11 0b 11 16 91 13 1c 11 15 11 1b 6f ?? ?? ?? 0a 13 1d 11 0b 11 0a 17 58 11 14 5d 91 13 1e 11 1c 11 1d 61 11 1e 59 20 00 01 00 00 58 13 1f 11 0b 11 16 11 1f 20 00 01 00 00 5d d2 9c 11 0a 17 59 13 0a 11 0a 16 fe 04 16 fe 01 13 20 11 20 2d a2}  //weight: 2, accuracy: Low
        $x_1_2 = "QuanLyKhoBanhKeo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDN_2147890116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDN!MTB"
        threat_id = "2147890116"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cc7fad03-816e-432c-9b92-001f2d498885" ascii //weight: 1
        $x_1_2 = "server1" ascii //weight: 1
        $x_1_3 = "Important System File" ascii //weight: 1
        $x_1_4 = "Sys file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMAA_2147891901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMAA!MTB"
        threat_id = "2147891901"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 8e 69 5d 13 08 09 11 08 91 13 09 11 06 17 58 08 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMAA_2147891901_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMAA!MTB"
        threat_id = "2147891901"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 58 08 5d 13 ?? 07 11 ?? 02 07 11 ?? 91 11 ?? 61 07 11 ?? 91 59 28 ?? ?? 00 06 28 ?? ?? 00 ?? 9c [0-1] 11 ?? 17 58 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMAA_2147891901_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMAA!MTB"
        threat_id = "2147891901"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 08 09 5d 13 09 11 08 11 04 5d 13 0a 07 11 09 91 13 0b 08 11 0a 6f ?? 00 00 0a 13 0c 02 07 11 08 28 ?? 00 00 06 13 0d 02 11 0b 11 0c 11 0d 28 ?? 00 00 06 13 0e 07 11 09 11 0e 20 00 01 00 00 5d d2 9c 11 08 17 59 13 08 11 08 16 2f b2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMAB_2147892942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMAB!MTB"
        threat_id = "2147892942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 04 05 28 ?? 00 00 06 0a 0e ?? 03 6f ?? 00 00 0a 59 0b 03 06 07 28 ?? 00 00 06 2a}  //weight: 4, accuracy: Low
        $x_1_2 = {4c 00 6f 00 61 00 64 00 00 21 47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMAB_2147892942_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMAB!MTB"
        threat_id = "2147892942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 07 8e 69 5d 13 05 11 04 08 6f ?? 00 00 0a 5d 13 06 07 11 05 91 13 07 08 11 06 6f ?? 00 00 0a 13 08 02 07 11 04 28 ?? 00 00 06 13 09 02 11 07 11 08 11 09 28 ?? 00 00 06 13 0a 07 11 05 02 11 0a 28 ?? 00 00 06 9c 11 04 17 59 13 04 11 04 16 2f ad}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MBJZ_2147893070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MBJZ!MTB"
        threat_id = "2147893070"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 0c 12 02 28 ?? 00 00 06 26 07 08 8f ?? 00 00 01 25 4a 17 58 54 12 06 28 ?? 00 00 0a 2d da}  //weight: 1, accuracy: Low
        $x_1_2 = "e721ac8abe44" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_ASDY_2147893076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ASDY!MTB"
        threat_id = "2147893076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 19 07 11 15 17 58 09 5d 91 13 1a 11 18 11 19 11 1a 28}  //weight: 2, accuracy: High
        $x_1_2 = {06 13 1b 07 11 16 11 1b 20 00 01 00 00 5d d2 9c}  //weight: 1, accuracy: High
        $x_1_3 = {11 15 09 5d 13 16 11 15 11 04 5d 13 17 07 11 16 91 13 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AKAO_2147894983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AKAO!MTB"
        threat_id = "2147894983"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 07 07 8e 69 6a 5d d4 91 08 11 07 08 8e 69 6a 5d d4 91 61 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 59}  //weight: 2, accuracy: High
        $x_1_2 = "Prototype.DEACT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMBA_2147895535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMBA!MTB"
        threat_id = "2147895535"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 09 11 0f 11 07 5d d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMBA_2147895535_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMBA!MTB"
        threat_id = "2147895535"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 04 61 05 59 20 ?? ?? 00 00 58}  //weight: 1, accuracy: Low
        $x_1_2 = {02 03 61 04 59 20 ?? ?? 00 00 58}  //weight: 1, accuracy: Low
        $x_1_3 = {11 0e 08 11 08 1f 16 5d 91 61 13 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Formbook_AMBA_2147895535_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMBA!MTB"
        threat_id = "2147895535"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 00 30 00 34 00 31 00 33 00 30 00 30 00 43 00 42 00 30 00 39 00 41 00 44 00 30 00 34 00 31 00 31 00 30 00 30 00 43 00 30 00 30 00 41 00 32 00 34 00 30 00 35 00 31 00 33 00 30 00 31 00 43 00 41 00 30 00 41 00 32 00 37 00 30 00 35 00 31 00 33 00 30 00 31 00 44 00 45 00 30 00 41 00 32 00 42 00 30 00 35 00 31 00 33 00 30 00 31 00 5a 00 32 00 30 00 41 00 32}  //weight: 1, accuracy: High
        $x_1_2 = "60B330513011A0B370513012E0B33051301420B3B051301560B3" wide //weight: 1
        $x_1_3 = {07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_ASF_2147896127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ASF!MTB"
        threat_id = "2147896127"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0b 2b 2a 08 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 16 91 13 09 11 04 11 09 6f ?? ?? ?? 0a 07 18 58 0b 07 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a fe 04 13 0a 11 0a 2d c2}  //weight: 2, accuracy: Low
        $x_1_2 = "QuanLyBanVeMayBay" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDH_2147896468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDH!MTB"
        threat_id = "2147896468"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "40b26aa4-9731-48d1-a198-ecb751bb4c4e" ascii //weight: 1
        $x_1_2 = "7!0yEK-)s@0G1^M\\*\\\\QZE/ZwP0" ascii //weight: 1
        $x_1_3 = "N556736" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_SQ_2147897487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.SQ!MTB"
        threat_id = "2147897487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 09 11 05 5d 13 0a 11 09 17 58 13 0b 08 11 0a 91 13 0c 08 11 0a 11 0c 09 11 09 1f 16 5d 91 61 08 11 0b 11 05 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 09 17 58 13 09 11 09 11 05 11 04 17 58 5a fe 04 13 0d 11 0d 2d b1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDO_2147897625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDO!MTB"
        threat_id = "2147897625"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppService_Broker" ascii //weight: 1
        $x_1_2 = "frmXoaDanhMuc" ascii //weight: 1
        $x_1_3 = "frmTrichDanNhieu" ascii //weight: 1
        $x_1_4 = "BaiBao" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MBFM_2147899002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MBFM!MTB"
        threat_id = "2147899002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 1b 03 04 61 05 59 20 00 01 00 00 58 0a 07}  //weight: 1, accuracy: High
        $x_1_2 = {4d 56 65 00 63 75 72 72 65 6e 74 56 61 6c 75 65 00 70 73 56 61 6c 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_DR_2147899383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.DR!MTB"
        threat_id = "2147899383"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$214e3bf3-8c27-44fc-b7c7-60fa631c7ffd" ascii //weight: 1
        $x_1_2 = "LMS_gui.Resources" ascii //weight: 1
        $x_1_3 = "databaseConnectionString" ascii //weight: 1
        $x_1_4 = "GetDomain" ascii //weight: 1
        $x_1_5 = "AutomationLiveRegion" ascii //weight: 1
        $x_1_6 = "WebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NA_2147899700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NA!MTB"
        threat_id = "2147899700"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {93 61 1f 50 5f 9d 30 04 16 0c 2b b4 09 20 26 ?? ?? ?? 93 20 cb ?? ?? ?? 59 2b ee 03 2b 01 02 0a 06 2a}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NNL_2147899703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NNL!MTB"
        threat_id = "2147899703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0e 04 11 02 0e 05 58 03 11 02 04 58 91 02 28 9c ?? ?? ?? 11 03 11 00 5d 91 61 d2 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NAL_2147899705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NAL!MTB"
        threat_id = "2147899705"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 06 08 06 08 91 07 08 07 8e 69 5d 93 61 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d e1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAC_2147900007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAC!MTB"
        threat_id = "2147900007"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 06 07 03 07 91 04 07 04 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 03 8e 69 fe 04 0c 08 2d e1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_CCGH_2147900258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.CCGH!MTB"
        threat_id = "2147900258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0e 04 28 06 00 00 06 00 7e ?? ?? ?? ?? 6f ?? 00 00 0a 05 16 03 8e 69 6f ?? 00 00 0a 0a 06 28 ?? 00 00 0a 00 06 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NN_2147900359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NN!MTB"
        threat_id = "2147900359"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 00 09 17 58 0d 09 1d fe 02 16 fe 01 13 04 11 04 2d cf}  //weight: 5, accuracy: High
        $x_5_2 = {00 09 11 05 07 ?? ?? ?? ?? ?? 9c 00 11 05 17 58 13 05 11 05 11 04 fe 02 16 fe 01 13 06 11 06 2d df}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PTEX_2147900384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PTEX!MTB"
        threat_id = "2147900384"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 90 00 00 0a 17 73 6b 00 00 0a 25 02 16 02 8e 69 6f 91 00 00 0a 6f 92 00 00 0a 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NM_2147901368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NM!MTB"
        threat_id = "2147901368"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 38 b1 f4 ff ff 07 11 0a 91 11 07 58 13 0d 07 11 09 11 0b 11 0c 61 11 0d 11 07 5d 59 d2 9c 11 0f 20 c1 67 4b 2e 5a 20 82 fd a3 32 61 38 85 f4 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_LA_2147901730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.LA!MTB"
        threat_id = "2147901730"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "//107.172.31.179/500" ascii //weight: 5
        $x_1_2 = "Invoke" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
        $x_1_5 = "Mock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMBF_2147901912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMBF!MTB"
        threat_id = "2147901912"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 61 07 11 ?? 20 ?? ?? ?? ?? 5d 91 11 ?? 58 11 ?? 5d 59 d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDP_2147902329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDP!MTB"
        threat_id = "2147902329"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Animal_Identify2" ascii //weight: 1
        $x_1_2 = "Compatibility Database" ascii //weight: 1
        $x_1_3 = "Xem_hinh_form" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAG_2147902340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAG!MTB"
        threat_id = "2147902340"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 61 06 11 ?? 20 00 ?? ?? 00 5d 91 20 00 ?? 00 00 58 20 00 ?? 00 00 5d 59 d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAE_2147902501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAE!MTB"
        threat_id = "2147902501"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 09 61 d1 6f ?? 00 00 0a 26 00 11 08 17}  //weight: 1, accuracy: Low
        $x_1_2 = {8e 69 5d 91 61 d2 52 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_XZ_2147902637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.XZ!MTB"
        threat_id = "2147902637"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {12 01 28 63 00 00 0a 0c 08 6f 56 00 00 06 00 12 01 28 64 00 00 0a 2d e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAF_2147902684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAF!MTB"
        threat_id = "2147902684"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 18 d8 0a 06 1f ?? fe ?? 0d 09 2c ?? 1f ?? 0a 00 06 1f ?? 5d 16 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAH_2147902785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAH!MTB"
        threat_id = "2147902785"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 8e 69 5d 11 ?? 20 00 01 00 00 5d d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MBFU_2147902907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MBFU!MTB"
        threat_id = "2147902907"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 00 67 00 68 00 68 00 67 00 6a 00 36 00 36 00 00 03 5c 00 00 11 56 00 62 00 6e 00 67 00 68 00 6a 00 37 00 36}  //weight: 1, accuracy: High
        $x_1_2 = {72 00 00 05 65 00 73 00 00 05 6f 00 75 00 00 05 72 00 63 00 00 0d 39 00 30 00 75 00 6b 00 6a 00 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_SPCJ_2147903224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.SPCJ!MTB"
        threat_id = "2147903224"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 8e 69 6a 5d d4 91 61 28 ?? ?? ?? 0a 07 11 05 17 6a 58 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDQ_2147903909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDQ!MTB"
        threat_id = "2147903909"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 0b d4 91 61 28 ?? ?? ?? ?? 07 11 09 08 6a 5d d4 91}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDR_2147904300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDR!MTB"
        threat_id = "2147904300"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 10 d4 91 61 07 11 0e 11 0c 6a 5d d4 91}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_CCHT_2147904392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.CCHT!MTB"
        threat_id = "2147904392"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0c 11 0d 61 13 0f 20 1c 00 00 00 fe 0e ?? 00 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDT_2147904587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDT!MTB"
        threat_id = "2147904587"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {61 07 11 06 17 6a 58 07 8e 69 6a 5d d4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAI_2147904678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAI!MTB"
        threat_id = "2147904678"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 61 07 11 ?? 17 6a 58 07 8e 69 6a 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDU_2147904691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDU!MTB"
        threat_id = "2147904691"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 11 10 d4 91 61 06 11 0f 11 08 6a 5d d4 91}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMMB_2147904784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMMB!MTB"
        threat_id = "2147904784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5d d4 91 08 11 ?? 69 1f ?? 5d 6f ?? 00 00 0a 61 07 11}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDV_2147904847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDV!MTB"
        threat_id = "2147904847"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {61 11 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0b 07 11 09 11 08 6a 5d d4 11 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDW_2147905061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDW!MTB"
        threat_id = "2147905061"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 5d 13 07 07 11 07 91 08 11 06 1f 16 5d 91 61}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDX_2147905250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDX!MTB"
        threat_id = "2147905250"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 0c 11 0c 61 11 0b 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0d 07 11 0a 11 0d d2 9c 11 0a 17 58 13 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDY_2147905342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDY!MTB"
        threat_id = "2147905342"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 0e 11 0e 61 11 0d 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0f 07 11 07 11 0f d2 9c 11 07 17 58 13 07 11 0c 17 58 13 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDZ_2147905458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDZ!MTB"
        threat_id = "2147905458"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 09 11 0b 61 11 0a 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0c 07 11 04 11 0c d2 9c 11 04 17 58 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAA_2147905549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAA!MTB"
        threat_id = "2147905549"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 0b 11 08 11 0b 61 11 0a 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0c 07 09 11 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAB_2147905620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAB!MTB"
        threat_id = "2147905620"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 08 11 08 61 11 07 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 09 06 07 11 09 d2 9c 07 17 58 0b 08 17 58 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_SDF_2147905683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.SDF!MTB"
        threat_id = "2147905683"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {58 07 8e 69 5d 91 13 06 08 11 05 08 8e 69 5d 91 13 07 07 11 05 07 11 05 91 11 07 61 11 06 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAC_2147905777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAC!MTB"
        threat_id = "2147905777"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 1f 16 5d 91 13 07 07 06 07 06 91 11 07 61 11 06 59 20 00 01 00 00 58 d2 9c 06 17 58 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAD_2147905785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAD!MTB"
        threat_id = "2147905785"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 37 00 00 0a 59 d2 9c 11 04 17 58 13 04 11 04 11 07 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAE_2147906002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAE!MTB"
        threat_id = "2147906002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 11 05 1f 16 5d 91 13 08 07 11 05 07 11 05 91 11 08 61 11 07 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAF_2147906085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAF!MTB"
        threat_id = "2147906085"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 09 1f 16 5d 91 13 06 07 09 07 09 91 11 06 61 11 05 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 09 17 58 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAJ_2147906250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAJ!MTB"
        threat_id = "2147906250"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 02 6f ?? 00 00 0a 25 03 6f ?? 00 00 0a 6f ?? 00 00 0a 04 16 04 8e 69 6f ?? 00 00 0a 10 02 04 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MBZW_2147906991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MBZW!MTB"
        threat_id = "2147906991"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 8e 69 5d 91 59 20 00 01 00 00 58 d2 9c 07 11 [0-18] 91 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAH_2147907725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAH!MTB"
        threat_id = "2147907725"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 75 09 00 00 1b 1f 18 9a 6f 41 00 00 0a 0c 08 74 0a 00 00 1b 28 03 00 00 2b 0d 1a 13 09}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAI_2147908335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAI!MTB"
        threat_id = "2147908335"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 74 40 00 00 1b 6f 04 01 00 0a 28 0f 00 00 2b 28 10 00 00 2b 0a 06 74 41 00 00 1b 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PADT_2147908434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PADT!MTB"
        threat_id = "2147908434"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 91 61 07 08 17 58 11 05 5d 91 59 20 00 01 00 00 58 13 06 07 08 11 06 20 ff 00 00 00 5f}  //weight: 1, accuracy: High
        $x_1_2 = {28 aa 00 00 0a 9c 08 17 58 0c 00 08 07 8e 69 fe 04 13 07 11 07 2d 96}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAK_2147908737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAK!MTB"
        threat_id = "2147908737"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 17 58 11 ?? 5d 13 ?? 07 08 91 11 ?? 61 07 11 ?? 91 59 20 00 01 00 00 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAL_2147909412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAL!MTB"
        threat_id = "2147909412"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 06 08 03 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_SKI_2147909785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.SKI!MTB"
        threat_id = "2147909785"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 51 00 00 70 6f 41 00 00 0a 0b 16 0c 2b 16 00 06 08 0e 04 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 04 8e 69 fe 04 0d 09 2d e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAJ_2147909878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAJ!MTB"
        threat_id = "2147909878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Omaxltn" ascii //weight: 1
        $x_1_2 = "//bestsoftwaredownloads.com/panel/uploads" wide //weight: 1
        $x_1_3 = "QiS6grnSOLTIgQV53nQOuw==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAK_2147910065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAK!MTB"
        threat_id = "2147910065"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 5d 13 0f 07 11 0c 02 07 11 0c 91 11 0e 61 07 11 0f 91 59}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAL_2147910391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAL!MTB"
        threat_id = "2147910391"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 5b 00 00 0a 13 04 73 5c 00 00 0a 0c 08 11 04 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAN_2147910572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAN!MTB"
        threat_id = "2147910572"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {58 08 5d 13 ?? 02 07 11 ?? 91 11 ?? 61 07 11 ?? 91 59 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PADW_2147911277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PADW!MTB"
        threat_id = "2147911277"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 02 07 91 04 07 04 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAO_2147911473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAO!MTB"
        threat_id = "2147911473"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 07 06 91 11 ?? 61 07 06 17 58 09 5d 91}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_GPA_2147912246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.GPA!MTB"
        threat_id = "2147912246"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FG5PG8FR4848TVZ3A5GZO4" ascii //weight: 1
        $x_1_2 = {17 58 07 8e 69 5d 91 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RF_2147912351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RF!MTB"
        threat_id = "2147912351"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {14 91 08 11 ?? 08 8e 69 5d 91 61 d2 9c 00 11}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PAEK_2147912687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PAEK!MTB"
        threat_id = "2147912687"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 05 11 06 09 11 06 11 04 95 9e 11 06 11 04 11 05 9e 07 11 0e d4 91 13 0f 11 06 09 95 11 06 11 04 95 58 d2 13 10 11 10 20 ff 00 00 00 5f d2 13 11 11 06 11 11 95 d2 13 12 11 07 11 0e d4 11 0f 6e 11 12 20 ff 00 00 00 5f 6a 61 d2 9c 00 11 0e 17 6a 58 13 0e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PAET_2147913245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PAET!MTB"
        threat_id = "2147913245"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 04 91 11 06 61 13 07 11 04 17 58 13 08 07 11 08 11 05 5d 91 13 09 20 00 01 00 00 13 0a 11 07 11 09 59 11 0a 58 11 0a 17 59 5f 13 0b 07 11 04 11 0b d2 9c 00 11 04 17 58 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAP_2147913669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAP!MTB"
        threat_id = "2147913669"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 07 17 59 94 0d 08 07 94 09 59 06 7b 55 00 00 04 8e 69 59 13 04 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAQ_2147914160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAQ!MTB"
        threat_id = "2147914160"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 04 00 00 04 06 91 03 06 03 8e 69 5d 91 61 d2 9c 00 06 17 58 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAR_2147915012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAR!MTB"
        threat_id = "2147915012"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 09 91 11 07 61 13 1a 07 09 17 58 08 5d 91}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMAI_2147915081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMAI!MTB"
        threat_id = "2147915081"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 02 16 03 8e 69 6f ?? 00 00 0a 0b 07 28 ?? 00 00 0a 0c 08 6f ?? 00 00 0a 0d 09 16 9a 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMAJ_2147915324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMAJ!MTB"
        threat_id = "2147915324"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 5d 91 13 ?? 07 09 91 11 ?? 61 09 18 58 17 59 08 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NBL_2147915612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NBL!MTB"
        threat_id = "2147915612"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 09 07 8e 69 5d 91 08 09 08 6f 5e 00 00 0a 5d 6f 5f 00 00 0a 61 07 09 17 58 07 8e 69 5d 91 59 20 00 01 00 00 58 13 07 07 09 07 8e 69 5d 11 07 20 00 01 00 00 5d d2 9c 09 15 58 0d 09 16 2f c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MBXM_2147915854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MBXM!MTB"
        threat_id = "2147915854"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 07 11 09 11 0b 59 20 00 01 00 00 58 20 ff 00 00 00 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_SGRG_2147916053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.SGRG!MTB"
        threat_id = "2147916053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 11 07 09 8e 69 5d 91 13 08 07 11 07 91 11 08 61 13 09 11 07 17 58 08 5d 13 0a 07 11 0a 91 13 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMAO_2147916083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMAO!MTB"
        threat_id = "2147916083"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 58 09 8e 69 5d 91 13 ?? 07 11 ?? 08 5d 08 58 08 5d 91 11 ?? 61 [0-5] 17 58 08 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAS_2147916256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAS!MTB"
        threat_id = "2147916256"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 08 16 73 6d 00 00 0a 13 04 03 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMAP_2147916312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMAP!MTB"
        threat_id = "2147916312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 58 06 5d 13 [0-15] 61 [0-15] 17 58 06 58 06 5d [0-32] 59 20 00 01 00 00 58 20 00 01 00 00 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMAR_2147916542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMAR!MTB"
        threat_id = "2147916542"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 58 08 5d 91 [0-30] 08 5d 08 58 08 5d 91 [0-5] 61 [0-30] 20 00 01 00 00 5d [0-9] 20 00 01 00 00 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMAS_2147916729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMAS!MTB"
        threat_id = "2147916729"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 95 d2 13 [0-15] 61 [0-30] 20 ff 00 00 00 5f d2 9c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAM_2147916730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAM!MTB"
        threat_id = "2147916730"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 95 d2 13 ?? ?? ?? ?? ?? 61 13 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 59 [0-14] 20 ff 00 00 00 5f d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAT_2147917425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAT!MTB"
        threat_id = "2147917425"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 5d 13 0e 07 11 0e 91 13 0f 11 0f 11 0a 61 13 10 11 10 11 0d 59}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_GPB_2147917721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.GPB!MTB"
        threat_id = "2147917721"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 da 0c 16 0d 2b 17 07 09 07 09 6f ?? 00 00 0a 1f 33 61 b4 6f 94}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAO_2147917970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAO!MTB"
        threat_id = "2147917970"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 5d 08 58 08 5d 13 [0-15] 61 [0-5] 59 20 00 02 00 00 58 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMAC_2147918686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMAC!MTB"
        threat_id = "2147918686"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 5d 08 58 13 [0-40] 08 5d 08 58 13 [0-30] 08 5d [0-30] 61 [0-40] 20 00 01 00 00 5d 20 00 04 00 00 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAU_2147918799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAU!MTB"
        threat_id = "2147918799"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 03 6f 49 00 00 0a 8e 69 6f 4d 00 00 0a 28 08 00 00 2b 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMAD_2147918876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMAD!MTB"
        threat_id = "2147918876"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 58 08 5d [0-15] 08 58 08 5d 91 [0-40] 5a 58 08 5d 13 [0-20] 61 [0-15] 59 20 00 02 00 00 58 13 [0-30] 20 00 01 00 00 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AY_2147919379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AY!MTB"
        threat_id = "2147919379"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 06 11 07 6f ?? 00 00 0a 13 08 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 20 ?? ?? ?? 00 2f 0d 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 20 ?? ?? ?? 00 2f 0d 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 11 07 17 58 13 07 11 07 07 6f ?? 00 00 0a 32 a3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAV_2147919771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAV!MTB"
        threat_id = "2147919771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 6f 48 00 00 0a 28 49 00 00 0a 0c 08 6f 4a 00 00 0a 16 9a 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMAG_2147919823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMAG!MTB"
        threat_id = "2147919823"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 07 11 05 11 06 6f ?? 00 00 0a 13 07 08 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 1f 61 13 0d}  //weight: 2, accuracy: Low
        $x_1_2 = {08 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0f 18 91 13 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAW_2147920020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAW!MTB"
        threat_id = "2147920020"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "e1115e9c-302f-4389-a279-95dea3056106" ascii //weight: 2
        $x_2_2 = "ESSUserChanger" ascii //weight: 2
        $x_1_3 = "bishopTransform" ascii //weight: 1
        $x_1_4 = "horseTransform" ascii //weight: 1
        $x_1_5 = "kingInCheck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_OKA_2147920470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.OKA!MTB"
        threat_id = "2147920470"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 11 05 11 06 9e 11 04 11 07 95 11 04 11 05 95 58 20 ff 00 00 00 5f 13 13 11 04 11 13 95 d2 13 14 09 11 12 07 11 12 91 11 14 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_SPSG_2147921748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.SPSG!MTB"
        threat_id = "2147921748"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 18 fe 04 16 fe 01 0b 07 2c 0e 02 0f 01 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 04 19 fe 01 0c 08 2c 0e 02 0f 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAQ_2147921801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAQ!MTB"
        threat_id = "2147921801"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {95 58 20 ff 00 00 00 5f [0-30] 95 61 28 ?? 00 00 0a 9c [0-35] 09 8e 69 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAR_2147922120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAR!MTB"
        threat_id = "2147922120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 08 59 0d 09 16 30 03 16 2b 01 17 13 04 08 19 58 04 fe 02 16 fe 01 13 05 11 05 2c 07 11 04 17 fe 01 2b 01 16 13 06 11 06 2c 0f 00 03 07 28 ?? 00 00 06 00 00 38 ?? 00 00 00 00 09 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMN_2147923306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMN!MTB"
        threat_id = "2147923306"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {95 58 20 ff 00 00 00 5f 13 [0-30] 95 61 28 ?? 00 00 0a 9c 11 ?? 17 58 13 [0-15] 6e 09 8e 69 6a fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PNEH_2147924300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PNEH!MTB"
        threat_id = "2147924300"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 04 11 04 2c 2f 00 03 19 8d 5b 00 00 01 25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 6f 75 00 00 0a 00 00 2b 41}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAX_2147924458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAX!MTB"
        threat_id = "2147924458"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 02 6f 18 00 00 0a 16 02 6f 1a 00 00 0a 6f 1b 00 00 0a 28 05 00 00 2b 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAT_2147924639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAT!MTB"
        threat_id = "2147924639"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 5a 58 20 00 ?? 00 00 5e 13 05 04 08 03 08 91 05 09 95 61 d2 9c 04 08 91 11 05 58 1f 33 61 20 ?? 00 00 00 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_SVCF_2147925005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.SVCF!MTB"
        threat_id = "2147925005"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 03 08 09 28 ?? 00 00 06 03 08 09 28 ?? 00 00 06 03 6f ?? 00 00 0a 04 32 01 2a 07 17 58 0b 07 02 6f ?? 00 00 0a 32 c7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RDAY_2147925016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RDAY!MTB"
        threat_id = "2147925016"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 06 07 28 0c 00 00 06 0c 04 03 6f 1d 00 00 0a 59 0d 03 08 09}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MBXX_2147925156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MBXX!MTB"
        threat_id = "2147925156"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 06 07 28 ?? ?? ?? ?? 0c 04 03 6f ?? ?? ?? ?? 59 0d 03 08 09}  //weight: 4, accuracy: Low
        $x_3_2 = "System.Reflection.Assembly" wide //weight: 3
        $x_2_3 = {4c 00 6f 00 61 00 64}  //weight: 2, accuracy: High
        $x_1_4 = "GetPixelColor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MBXY_2147925167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MBXY!MTB"
        threat_id = "2147925167"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 16 0f 01 28 ?? 01 00 0a 9c 25 17 0f 01 28 ?? 01 00 0a 9c 25 18 0f 01 28 ?? 01 00 0a 9c 0d 02 09 04}  //weight: 10, accuracy: Low
        $x_1_2 = {4c 00 6f 00 61 00 64}  //weight: 1, accuracy: High
        $x_1_3 = "ProcessBitmap" ascii //weight: 1
        $x_1_4 = "GetPixelColor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_CCJN_2147925251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.CCJN!MTB"
        threat_id = "2147925251"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 16 05 a2 28 ?? 00 00 0a 26 06 72 ?? ?? ?? ?? 18 18 8d ?? ?? ?? ?? 25 16 04 a2 25 17 05 a2 28 ?? 00 00 0a 0b 03 73 ?? ?? ?? ?? 0c 08 07 74 ?? 00 00 01 16 73 ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 00 09 11 04 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 13 05 de 23 11 04 2c 08 11 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PNYH_2147925391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PNYH!MTB"
        threat_id = "2147925391"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 02 06 07 28 ?? ?? ?? ?? 0c 04 03 6f ?? ?? ?? ?? 59 0d 03 08 09 28 ?? ?? ?? ?? 00 00 07 17 58 0b 07 02 6f ?? ?? ?? ?? 2f 0b 03 6f ?? ?? ?? ?? 04 fe 04 2b 01 16 13 04 11 04 2d c4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PMTH_2147926154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PMTH!MTB"
        threat_id = "2147926154"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 00 06 06 6f ?? ?? ?? ?? 06 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 0b 73 ?? ?? ?? ?? 0c 08 07 17 73 ?? ?? ?? ?? 0d 00 09 02 16 02 8e 69 6f ?? ?? ?? ?? 00 09 6f ?? ?? ?? ?? 00 08 6f ?? ?? ?? ?? 13 04 dd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMAE_2147926309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMAE!MTB"
        threat_id = "2147926309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 20 00 01 00 00 5e 13 [0-20] 17 13 [0-30] 95 61 d2 9c 11 [0-20] 17 58 13 [0-10] 07 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMCL_2147926916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMCL!MTB"
        threat_id = "2147926916"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 14 0d 14 13 04 [0-30] 6f ?? 00 00 0a 00 11 04 08 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 13 0c 11 0c 02 16 02 8e 69 6f ?? 00 00 0a 0a de 53}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMCN_2147927108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMCN!MTB"
        threat_id = "2147927108"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 0b 2b 91 11 04 ?? ?? 00 00 01 6f ?? 00 00 0a 13 05 11 05 ?? ?? 00 00 01 02 16 02 8e 69 6f ?? 00 00 0a 13 06 ?? 13 0b 38}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMCP_2147927591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMCP!MTB"
        threat_id = "2147927591"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 08 28 ?? 00 00 06 a2 28 ?? 00 00 0a 75}  //weight: 4, accuracy: Low
        $x_4_2 = {34 00 44 00 35 00 41 00 39 00 3a 00 30 00 33 00 3a 00 3a 00 30 00 34 00 3a 00 3a 00 46 00 46 00 46 00 46 00 3a 00 30 00 42 00 38 00 3a 00 3a 00 3a 00 3a 00 30 00 30 00 34 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a}  //weight: 4, accuracy: High
        $x_2_3 = {4c 00 6f 00 67 00 69 00 6e 00 00 09 4c 00 6f 00 61 00 64 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMCQ_2147927749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMCQ!MTB"
        threat_id = "2147927749"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 09}  //weight: 2, accuracy: Low
        $x_1_2 = {01 25 16 11 05 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 05 1e 63 20 ff 00 00 00 5f d2 9c 25}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAU_2147927987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAU!MTB"
        threat_id = "2147927987"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 16 11 0e 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 0e 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 0e 20 ff 00 00 00 5f d2 9c 6f ?? 00 00 0a 11 0f 16 94}  //weight: 1, accuracy: Low
        $x_1_2 = {25 16 12 0a 28 ?? 00 00 0a 9c 25 17 12 0a 28 ?? 00 00 0a 9c 25 18 12 0a 28 ?? 00 00 0a 9c 11 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PQIH_2147928002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PQIH!MTB"
        threat_id = "2147928002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {25 16 11 18 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 18 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 18 20 ff 00 00 00 5f d2 9c 6f ?? 00 00 0a 00 11 19 16 94}  //weight: 6, accuracy: Low
        $x_5_2 = {25 16 12 0c 28 ?? 00 00 0a 9c 25 17 12 0c 28 ?? 00 00 0a 9c 25 18 12 0c 28 ?? 00 00 0a 9c 11 0e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PKNH_2147928170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PKNH!MTB"
        threat_id = "2147928170"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {25 16 11 0c 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 11 0c 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 11 0c 20 ?? 00 00 00 5f d2 9c}  //weight: 6, accuracy: Low
        $x_4_2 = {30 02 2b 68 11 05 20 ?? 07 00 00 5a 11 09 61 13 05 08 1f 1f 62 08 1f 21 64 60 0c 03 19 8d ?? 00 00 01 25 16 12 06 28 ?? 00 00 0a 9c 25 17 12 06 28 ?? 00 00 0a 9c 25 18 12 06 28 ?? 00 00 0a 9c 11 08}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AMCT_2147928220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AMCT!MTB"
        threat_id = "2147928220"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 00 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 00 09 02 16 02 8e 69 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 00 08 6f ?? 00 00 0a 13 04 de 2c}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAV_2147928546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAV!MTB"
        threat_id = "2147928546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {1a db 11 97 a4 44 53 03 2e 15 4d bf 59 c1 d4 b6 6c 15 83 22 c3 d1 68 e4 68 a0 d1}  //weight: 4, accuracy: High
        $x_3_2 = {ea 1a a3 bb 26 25 19 44 4e 03 81 a7 b5 59 d1 eb 12 88 37 27 cf e8 5d bb 7e 1a}  //weight: 3, accuracy: High
        $x_3_3 = "Olly" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PLLSH_2147930700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PLLSH!MTB"
        threat_id = "2147930700"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {04 19 32 50 0f 01 28 ?? 01 00 0a 1f 10 62 0f 01 28 ?? 01 00 0a 1e 62 60 0f 01 28 ?? 01 00 0a 60 0a 02 19 8d ?? 00 00 01 25 16 06 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 06 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 06 20 ?? 00 00 00 5f d2 9c 6f ?? 01 00 0a 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PLIEH_2147931173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PLIEH!MTB"
        threat_id = "2147931173"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 1f 10 62 0f 00 28 ?? 00 00 0a 1e 62 60 0f 00 28 ?? 00 00 0a 60 0a 03 19 8d ?? 00 00 01 25 16 06 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 06 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 06 20 ?? 00 00 00 5f d2 9c 6f ?? 00 00 0a 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_KAW_2147931295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.KAW!MTB"
        threat_id = "2147931295"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {25 16 02 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 02 1e 63 20 ff 00 00 00 5f d2 9c 25 18 02 20 ff 00 00 00 5f d2 9c 0a 2b 00}  //weight: 3, accuracy: High
        $x_2_2 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0a 2b 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_AUJ_2147931781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.AUJ!MTB"
        threat_id = "2147931781"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 11 05 9a 28 81 01 00 0a 20 98 00 00 00 da b4 13 06 09 11 06 6f 82 01 00 0a 00 11 05 17 d6 13 05 11 05 11 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_PLIOH_2147931917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.PLIOH!MTB"
        threat_id = "2147931917"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 08 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 04 16 2d 0e 2b 21 2b 23 16 2b 23 8e 69 6f ?? 00 00 0a 73 22 00 00 0a 25 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 de 30}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_NOS_2147932117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.NOS!MTB"
        threat_id = "2147932117"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 2d 0a 04 1f 41 fe 04 16 fe 01 2b 01 17 0b}  //weight: 2, accuracy: High
        $x_1_2 = {25 17 6f 33 01 00 0a 0b 03 17 da 0d 18 13 04}  //weight: 1, accuracy: High
        $x_1_3 = {1f 7c 07 1b 5d 17 d6 ?? ?? 00 00 0a ?? ?? 00 00 0a 07 18 d6 0b 07 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_BO_2147936870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.BO!MTB"
        threat_id = "2147936870"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 07 02 6f ?? 00 00 0a 58 02 6f ?? 00 00 0a 5d 11 05 02 6f ?? 00 00 0a 58 02 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 13 07 04 03 6f ?? 00 00 0a 59 13 08 11 07 11 08 03}  //weight: 4, accuracy: Low
        $x_1_2 = {17 58 13 05 11 05 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MKB_2147938291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MKB!MTB"
        threat_id = "2147938291"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0c 11 0b 6f a8 01 00 0a 58 13 0c 11 24 17 d6 13 24 11 24 20 40 42 0f 00 31 e5 11 05 19 11 05 18 9a 74 75 00 00 1b 11 06 28 ?? 02 00 0a 28 ?? 01 00 06 14 72 52 17 00 70 16 8d 01 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a a2 23 00 00 00 00 00 00 00 00 13 0d 17 13 25 11 0d 11 25 6c 23 00 00 00 00 00 00 00 40 28 ?? 00 00 0a 58 13 0d 11 25 17 d6 13 25 11 25 20 a0 86 01 00 31 db}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_LLT_2147938376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.LLT!MTB"
        threat_id = "2147938376"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 72 61 00 00 70 28 0b 00 00 0a 6f 0c 00 00 0a 06 72 93 00 00 70 28 ?? 00 00 0a 6f 0d 00 00 0a 06 6f 0e 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 0b dd 0d 00 00 00 06 39 06 00 00 00 06 6f 10 00 00 0a dc 07 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_GPPG_2147938493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.GPPG!MTB"
        threat_id = "2147938493"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 58 0f 00 28 ?? 00 00 0a 58 6c 23 00 00 00 00 00 e8 87 40 5b 23 00 00 00 00 00 00 59 40 5a 0b}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_WVG_2147939617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.WVG!MTB"
        threat_id = "2147939617"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {19 8d 3b 00 00 01 25 16 02 7c 3c 00 00 04 28 7d 00 00 0a 9c 25 17 02 7c 3c 00 00 04 28 7f 00 00 0a 9c 25 18 02 7c 3c 00 00 04 28 ?? 00 00 0a 9c 0a 09 20 00 6b 69 29 5a 20 2c d3 66 d3 61 38 cf fe ff ff}  //weight: 5, accuracy: Low
        $x_4_2 = {11 0e 02 11 0b 11 0d 6f ?? 00 00 0a 7d 3c 00 00 04 11 0e 04 11 0e 7b 3e 00 00 04 7b 3b 00 00 04 6f ?? 00 00 0a 59 7d 3d 00 00 04 11 17 20 d6 38 3e 23 5a 20 8e 2b d1 3b 61 38 ab fb ff ff}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_BR_2147940998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.BR!MTB"
        threat_id = "2147940998"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {16 9a 16 99 5a a1 25 17}  //weight: 3, accuracy: High
        $x_2_2 = {16 99 d2 9c 25 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_ZKV_2147941316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ZKV!MTB"
        threat_id = "2147941316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {11 05 09 17 94 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 13 0a 11 0a 2d 95 08 08 61 0c 00 11 04 17 58 13 04 11 04 09 16 94 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 13 0b 11 0b}  //weight: 6, accuracy: Low
        $x_5_2 = {07 02 11 04 11 05 6f ?? 00 00 06 13 06 04 03 6f ?? 00 00 0a 59 13 07 11 07 19 28 ?? 00 00 06 13 08 11 08 2c 0d 00 03 11 06 28 ?? 00 00 06 00 00 2b 18 11 07 16 fe 02 13 09 11 09 2c 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_RA_2147941420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.RA!MTB"
        threat_id = "2147941420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MechMatrix Pro.dll" ascii //weight: 1
        $x_1_2 = "notepad.rtf" ascii //weight: 1
        $x_1_3 = "VtCWmcesEpHrvweaNP" ascii //weight: 1
        $x_1_4 = "Phantom Dimension Software" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_ZIU_2147942175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ZIU!MTB"
        threat_id = "2147942175"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 15 5f 13 09 11 09 06 17 17 28 ?? 00 00 0a 5a 06 17 16 28 ?? 00 00 0a 26 16 58 06 17 18 28 ?? 00 00 0a 26 16 58 13 0a 02 11 08 11 0a 6f ?? 00 00 0a 13 0b 12 0b 28 ?? 00 00 0a 13 0c 12 0b 28 ?? 00 00 0a 13 0d 12 0b 28 ?? 00 00 0a 13 0e 04 03 6f ?? 00 00 0a 59 13 0f 11 0f 19 fe 04 16 fe 01 13 10 11 10 2c 54}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_ZNU_2147942286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ZNU!MTB"
        threat_id = "2147942286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {26 16 58 06 17 18 28 ?? 00 00 0a 26 16 58 13 08 02 11 07 11 08 6f ?? 00 00 0a 13 09 12 09 28 ?? 00 00 0a 13 0a 12 09 28 ?? 00 00 0a 13 0b 12 09 28 ?? 00 00 0a 13 0c 04 03 6f ?? 00 00 0a 59 13 0d 11 0d 19 32 4f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_CE_2147942337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.CE!MTB"
        threat_id = "2147942337"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {41 00 51 00 3a 00 3a 00 3a 00 4f 00 44 00 36 00 35 00 41 00 34 00 41 00 46 00 55 00 42 00 48 00 47 00 53 00 44 00 4f 00 41 00 42 00 4a 00 54 00 47 00 53 00 43 00 56 00 44 00 49 00 4e 00 46 00 5a 00 53 00 41 00 34 00 44 00 53 00 4e 00 35 00 54 00 58 00 45 00 59}  //weight: 3, accuracy: High
        $x_2_2 = {4a 00 56 00 4e 00 4a 00 3a 00 41 00 44 00 3a 00 3a 00 41 00 42 00 3a 00 3a 00 41 00 50 00 37 00 37 00 59 00 3a 00 43 00 34 00 3a 00 3a 00 3a 00 3a 00 3a 00 41 00 43}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_CF_2147942400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.CF!MTB"
        threat_id = "2147942400"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5f 13 0b 02 11 0a 11 0b 6f ?? 01 00 0a 13 0c 12 0c 28 ?? 01 00 0a 16 61 d2 13 0d 12 0c 28 ?? 01 00 0a 16 61 d2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_SLER_2147942459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.SLER!MTB"
        threat_id = "2147942459"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 4f 00 00 06 28 2c 00 00 0a 0b 00 06 28 05 00 00 06 0c 08 39 0a 00 00 00 08 8e 16 fe 03 38 01 00 00 00 16 0d 09 39 0f 00 00 00 00 07 08 28 0a 00 00 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_ZSU_2147942638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ZSU!MTB"
        threat_id = "2147942638"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 11 07 6f ?? 00 00 0a 03 11 07 17 da 6f ?? 00 00 0a 28 ?? 00 00 0a 03 11 07 17 da 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 13 08 08 11 08 6f ?? 00 00 0a 00 11 07 17 d6 13 07 11 07 11 06 31 be}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_ZZT_2147942840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.ZZT!MTB"
        threat_id = "2147942840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {26 02 11 13 11 14 6f ?? 01 00 0a 13 16 11 0b 11 15 12 16 28 ?? 01 00 0a 6f ?? 01 00 0a 12 16 28 ?? 01 00 0a 13 17 12 16 28 ?? 01 00 0a 13 18 12 16 28 ?? 01 00 0a 13 19 11 17 11 18 58 11 19 58 26 04 03 6f ?? 01 00 0a 59 25 17 28 ?? 01 00 0a 8d db 00 00 01 26 19 28 ?? 01 00 0a 13 1a 11 1a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_MCB_2147943899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.MCB!MTB"
        threat_id = "2147943899"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 00 0d 20 00 4c 00 6f 00 61 00 64}  //weight: 1, accuracy: High
        $x_2_2 = {36 00 44 00 35 00 38 00 36 00 39 00 37 00 34 00 00 0d 37 00 41 00 36 00 31 00 37 00 41}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_EHYZ_2147945215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EHYZ!MTB"
        threat_id = "2147945215"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 61 d2 13 3a 12 38 ?? ?? ?? ?? ?? 06 61 d2 13 3b 11 39 07 1f 1f 5f 62 11 39 1e 07 59 1f 1f 5f 63 60 20 ff 00 00 00 5f 13 3c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Formbook_EKIW_2147946283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbook.EKIW!MTB"
        threat_id = "2147946283"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5a 0e 05 6c 5b ?? ?? ?? ?? ?? 02 5a 13 04 06 ?? ?? ?? ?? ?? 09 11 04 23 00 00 00 00 00 ?? ?? ?? 5a ?? ?? ?? ?? ?? 23 00 00 00 00 00 00 ?? ?? 5d d2 9c 09 17 58 0d 09 0e 05 32 ba}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

