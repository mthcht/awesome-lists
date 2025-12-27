rule Trojan_MSIL_Fareit_OBFU_2147795746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fareit.OBFU!MTB"
        threat_id = "2147795746"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$449BB57E-F37D-4207-99C4-5CCDAED0B95E" ascii //weight: 1
        $x_1_2 = {57 15 02 08 09 0a 00 00 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "StreamReader" ascii //weight: 1
        $x_1_4 = "BinaryReader" ascii //weight: 1
        $x_1_5 = "MemoryStream" ascii //weight: 1
        $x_1_6 = "ASCIIEncoding" ascii //weight: 1
        $x_1_7 = "Substring" ascii //weight: 1
        $x_1_8 = "Encoding" ascii //weight: 1
        $x_1_9 = "Convert" ascii //weight: 1
        $x_1_10 = "Invoke" ascii //weight: 1
        $x_1_11 = "Random" ascii //weight: 1
        $x_1_12 = "Assembly" ascii //weight: 1
        $x_1_13 = "Thread" ascii //weight: 1
        $x_1_14 = "BitConverter" ascii //weight: 1
        $x_1_15 = "StringBuilder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fareit_AD_2147797106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fareit.AD!MTB"
        threat_id = "2147797106"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {2f 00 00 00 e1 00 00 00 1f 01 00 00 13 01 00 00 03}  //weight: 3, accuracy: High
        $x_3_2 = "ChildWin" ascii //weight: 3
        $x_3_3 = "DockCtrl" ascii //weight: 3
        $x_3_4 = "set_passwordProtected" ascii //weight: 3
        $x_3_5 = "pre_Tracking_Number" ascii //weight: 3
        $x_3_6 = "Inject" ascii //weight: 3
        $x_3_7 = "Ui.TrackingRecord.resources" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fareit_MB_2147812737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fareit.MB!MTB"
        threat_id = "2147812737"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 0b 07 1f 20 8d 0d 00 00 01 25 d0 ?? ?? ?? 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 1f 10 8d 0d 00 00 01 25 d0 ?? ?? ?? 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 07 6f ?? ?? ?? 0a 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 06 28 ?? ?? ?? 06 0d 28 ?? ?? ?? 06 09 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "Reverse" ascii //weight: 1
        $x_1_8 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fareit_RPC_2147813206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fareit.RPC!MTB"
        threat_id = "2147813206"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GameWarden" wide //weight: 1
        $x_1_2 = "JVNJAAADAAAAABAAAAAP77YAAC4AAAAAAAAAAACAAAAAAAAAAAAAAAAAAA" wide //weight: 1
        $x_1_3 = "x121312x121312" ascii //weight: 1
        $x_1_4 = "_X_X_X_X_X_X_X_X_X_X_X_X_X_X_X_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fareit_OTF_2147817514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fareit.OTF!MTB"
        threat_id = "2147817514"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 01 00 00 04 07 7e 01 00 00 04 07 91 7e 02 00 00 04 07 7e 02 00 00 04 8e 69 5d 91 07 06 58 7e 02 00 00 04 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c 07 17 58 0b 07 7e 01 00 00 04 8e 69 32 bd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fareit_SPQ_2147837555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fareit.SPQ!MTB"
        threat_id = "2147837555"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 06 00 00 01 0a 06 25 0c 2c 05 08 8e 69 2d 05 16 e0 0b 2b 09 08 16 8f 06 00 00 01 e0 0b 07 02 54 14 0c 03 0d 09 2c 06 06 28 ?? ?? ?? 0a 06 13 04 11 04 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fareit_AF_2147889145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fareit.AF!MTB"
        threat_id = "2147889145"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 01 00 00 70 6f 11 00 00 0a 6f 12 00 00 0a 0b 07 2c 1c 28 13 00 00 0a 72 69 00 00 70 28 14 00 00 0a 25 07 28 15 00 00 0a 28 16 00 00 0a 26 de 0a 06 2c 06 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fareit_RS_2147899317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fareit.RS!MTB"
        threat_id = "2147899317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 06 91 8c 15 00 00 01 13 08 11 06 7e 16 00 00 04 8e b7 5d 8c 1a 00 00 01 13 07 07 11 06 11 08 7e 16 00 00 04 11 07 28 12 00 00 0a 91 8c 15 00 00 01 28 13 00 00 0a 28 14 00 00 0a 9c 11 06 17 58 13 06 11 06 11 09 31 b6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fareit_SG_2147901064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fareit.SG!MTB"
        threat_id = "2147901064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 08 06 8e 69 5d 06 08 06 8e 69 5d 91 07 08 07 8e 69 5d 91 61 06 08 17 58 06 8e 69 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 08 15 58 0c 08 16 2f cb}  //weight: 2, accuracy: High
        $x_1_2 = "Form1_Load" ascii //weight: 1
        $x_1_3 = "get_Culture" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Fareit_MCJ_2147954209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fareit.MCJ!MTB"
        threat_id = "2147954209"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {38 31 34 33 2d 64 36 63 66 30 65 37 35 37 66 30 64 00 00 0c 01 00 07 6e 65 77 61 73 73 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

