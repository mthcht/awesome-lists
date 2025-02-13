rule TrojanDownloader_MSIL_AveMariaRAT_E_2147827731_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.E!MTB"
        threat_id = "2147827731"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 16 02 8e 69 ?? 2d ?? 26 26 26 2b ?? 28 ?? 00 00 0a 2b 00 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {08 8e 69 6f ?? 00 00 0a 0d 12 ?? 08 09 28 ?? 00 00 06 09 16 fe ?? 13 ?? 11 ?? 2d ?? 11 ?? 6f ?? 00 00 0a 3a 00 06 6f ?? 00 00 0a 0b 20 ?? ?? ?? 00 8d ?? 00 00 01 0c 16 0d 07 08 16}  //weight: 1, accuracy: Low
        $x_1_3 = {00 00 0a 74 1b 00 00 01 ?? ?? 04 26 06 2b ?? 0a 2b fa 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AveMariaRAT_D_2147828365_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.D!MTB"
        threat_id = "2147828365"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 09 6f ?? 00 00 0a 80 ?? 00 00 04 16 13 ?? 2b ?? 00 7e ?? 00 00 04 11 ?? 7e ?? 00 00 04 11 04 91 20 ?? 02 00 00 59 d2 9c 00 11 ?? 17 58 13 ?? 11 ?? 7e ?? 00 00 04 8e 69 fe ?? 13 ?? 11 ?? 2d 67 00 72 ?? 00 00 70 28 ?? 00 00 0a 0a 06 6f ?? 00 00 0a 0b 07 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 08 09 6f}  //weight: 1, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AveMariaRAT_F_2147830127_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.F!MTB"
        threat_id = "2147830127"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 59 d2 9c 00 07 17 58 0b 07 7e ?? 00 00 04 8e 69 fe ?? 0c 08 7a 00 20 ?? ?? ?? 00 28 ?? 00 00 0a 00 73 ?? 00 00 0a 0a 06 72 ?? 00 00 70 6f ?? 00 00 0a 80 ?? 00 00 04 16 0b 2b ?? 00 7e ?? 00 00 04 07 7e ?? 00 00 04 07 91 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AveMariaRAT_G_2147830129_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.G!MTB"
        threat_id = "2147830129"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 0b 07 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 20 ?? ?? ?? 00 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 0d 06 6f ?? 00 00 0a 09 16 09 8e 69 6f}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 0a 0b 06 07 6f ?? 00 00 0a 0c de}  //weight: 2, accuracy: Low
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "GetMethod" ascii //weight: 1
        $x_1_5 = "CreateDelegate" ascii //weight: 1
        $x_1_6 = "DynamicInvoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AveMariaRAT_H_2147831385_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.H!MTB"
        threat_id = "2147831385"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 0a 06 16 06 8e 69 28 ?? 00 00 0a 02 06 28 ?? 00 00 0a 7d ?? 00 00 04 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 0a 06 03 73 ?? 00 00 0a 6f ?? 00 00 0a 0b de}  //weight: 2, accuracy: Low
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AveMariaRAT_I_2147831386_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.I!MTB"
        threat_id = "2147831386"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 0b 2b 2e 16 2b 2e 2b 33 2b 38 16 2d 09 2b 09 2b 0a 6f ?? 00 00 0a de 10 08 2b f4 07 2b f3 08 2c 06 08 6f ?? 00 00 0a dc 07 6f ?? 00 00 0a 0d de 2e 06 2b cf 73 ?? 00 00 0a 2b cb 73}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 0a 1c 2c 08 2b 08 2b 09 2b 0a 2b 0f de 23 06 2b f5 02 2b f4 6f ?? 00 00 0a 2b ef 0b 2b ee}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AveMariaRAT_M_2147831485_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.M!MTB"
        threat_id = "2147831485"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0c 08 20 00 01 00 00 6f ?? 00 00 0a 08 20 80 00 00 00 6f ?? 00 00 0a 28 ?? 00 00 0a 72 ?? ?? ?? 70 6f ?? 00 00 0a 06 20 e8 03 00 00 73 ?? 00 00 0a 0d 08 09 08 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 08 09 08 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 08 17 6f ?? 00 00 0a 07 08 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 04 11 04 02 16 02 8e 69 6f}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 0c 07 06 6f ?? 00 00 0a 0d 09 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 04 de}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AveMariaRAT_N_2147831845_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.N!MTB"
        threat_id = "2147831845"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 01 00 00 38 ?? 00 00 00 38 ?? 00 00 00 20 80 00 00 00 38 ?? 00 00 00 38 ?? 00 00 00 72 ?? ?? ?? 70 38 ?? 00 00 00 7e ?? 00 00 04 20 e8 03 00 00 73 ?? 00 00 0a 0c 07 08 07 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 1e 2c ?? 07 08 07 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 07 17 6f ?? 00 00 0a 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0d 09 02 16 02 8e 69 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AveMariaRAT_S_2147837685_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.S!MTB"
        threat_id = "2147837685"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 05 08 11 05 6f ?? 00 00 0a 11 04 17 58 13 04 11 04 09 6f ?? 00 00 0a 32 e0 14 08 28 ?? 00 00 2b 0d de 43 73}  //weight: 2, accuracy: Low
        $x_2_2 = {2b 0a 2b 0b 18 2b 0b 1f 10 2b 0e 2a 02 2b f3 03 2b f2 6f ?? 00 00 0a 2b ee 28}  //weight: 2, accuracy: Low
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AveMariaRAT_X_2147838645_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.X!MTB"
        threat_id = "2147838645"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 00 06 14 14 11 08 74}  //weight: 2, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "SecurityProtocolType" ascii //weight: 1
        $x_1_4 = "GetResponseStream" ascii //weight: 1
        $x_1_5 = "HttpWebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AveMariaRAT_Z_2147840916_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.Z!MTB"
        threat_id = "2147840916"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 09 09 94 11 09 11 05 94 58 20 00 01 00 00 5d 94 13 06 11 0a 11 04 07 11 04 91 11 06 61}  //weight: 2, accuracy: High
        $x_1_2 = "CreateDelegate" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AveMariaRAT_P_2147844628_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.P!MTB"
        threat_id = "2147844628"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8e 69 5d 91 02 11 04 91 61 d2 6f}  //weight: 2, accuracy: High
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AveMariaRAT_J_2147848601_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.J!MTB"
        threat_id = "2147848601"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GetExportedTypes" wide //weight: 2
        $x_2_2 = "Invoke" wide //weight: 2
        $x_2_3 = "Load" wide //weight: 2
        $x_2_4 = "://dbxviewer2020.000webhostapp.com/pure/uploads/" wide //weight: 2
        $x_2_5 = "Ljqwisdipifeibytyhqv" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AveMariaRAT_A_2147849805_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.A!MTB"
        threat_id = "2147849805"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Bbpykzvms.Properties.Resources.resources" ascii //weight: 2
        $x_2_2 = "jrm6ccnssaft39fa74x5jtue2rlxs8wa" ascii //weight: 2
        $x_2_3 = "qbdnpydk7an8j7mlugwq3b4knuf9ekju" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AveMariaRAT_K_2147850149_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.K!MTB"
        threat_id = "2147850149"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 8e 69 17 59 0c 2b ?? 0b 2b ?? 06 07 91 0d 06 07 06 08 91 9c 06 08 09 9c 07 17 58 0b 08 17 59 0c 07 08 32}  //weight: 2, accuracy: Low
        $x_1_2 = "ReadAsByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AveMariaRAT_V_2147852562_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.V!MTB"
        threat_id = "2147852562"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 11 0f 6f ?? 00 00 0a 13 10 12 0f 28 ?? 00 00 0a 28 ?? 00 00 0a 13 11 11 0a 11 10 11 11 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AveMariaRAT_AE_2147899404_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.AE!MTB"
        threat_id = "2147899404"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 08 06 08 91 20 ?? ?? ?? ?? 59 d2 9c 08 17 58 0c 08 06 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AveMariaRAT_NIT_2147925864_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMariaRAT.NIT!MTB"
        threat_id = "2147925864"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 72 09 01 00 70 28 ?? 00 00 0a 00 02 28 ?? 00 00 06 0a 72 35 01 00 70 28 ?? 00 00 0a 00 06 28 ?? 00 00 06 0b 07 2c 07 07 8e 16 fe 03 2b 01 16 0c 08 2c 16 00 72 91 01 00 70 28 ?? 00 00 0a 00 07 28 ?? 00 00 06 00 00 2b 0d 00 72 fd 01 00 70 28 ?? 00 00 0a 00 00 fe 13 7e 01 00 00 04 0d 09 2c 0e 00 72 47 02 00 70 28 ?? 00 00 0a 00 2b 2a 72 7d 02 00 70 28 ?? 00 00 0a 00 20 e8 03 00 00 28 ?? 00 00 0a 00 00 fe 13 7e 01 00 00 04 16 fe 01 13 04 11 04 3a 66 ff ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = {00 28 23 00 00 0a 28 ?? 00 00 0a 72 af 05 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 06 02 28 ?? 00 00 0a 00 06 73 27 00 00 0a 25 16 6f 28 ?? 00 0a 00 28 ?? 00 00 0a 26 00 de 1b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

