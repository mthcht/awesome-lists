rule TrojanDownloader_MSIL_BitRAT_E_2147827733_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BitRAT.E!MTB"
        threat_id = "2147827733"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 0a 25 02 6f ?? 00 00 0a 0a 6f ?? 00 00 0a 06 0b de}  //weight: 1, accuracy: Low
        $x_1_2 = {06 8e 69 8d ?? 00 00 01 0c 16 0d 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {08 09 07 09 07 8e 69 5d 91 06 09 91 61 d2 9c}  //weight: 1, accuracy: High
        $x_1_4 = "get_ASCII" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "GetType" ascii //weight: 1
        $x_1_7 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_BitRAT_H_2147830888_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BitRAT.H!MTB"
        threat_id = "2147830888"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 04 06 91 20 a0 03 00 00 59 d2 9c 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69 fe 04 0b 07 2d}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_BitRAT_ABL_2147831441_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BitRAT.ABL!MTB"
        threat_id = "2147831441"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 08 09 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 80 ?? ?? ?? 04 16 13 04 2b 1f 00 7e ?? ?? ?? 04 11 04 7e ?? ?? ?? 04 11 04 91 20 ?? ?? ?? 00 59 d2 9c 00 11 04 17 58 13 04 11 04 7e ?? ?? ?? 04 8e 69 fe 04 13 05 11 05 2d d0}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "AZLIJE8U3Y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_BitRAT_J_2147833233_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BitRAT.J!MTB"
        threat_id = "2147833233"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 02 11 00 6f ?? 00 00 0a 13 03 38 0d 00 00 00 11 01 18 6f ?? 00 00 0a 38 28 00 00 00 11 01 11 03 6f ?? 00 00 0a 38 e5 ff ff ff 11 01 6f 22 00 00 0a 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 38 08 00 00 00 02 13 04 38}  //weight: 2, accuracy: Low
        $x_1_2 = "GetType" ascii //weight: 1
        $x_1_3 = "GetMethod" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "GetResponseStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_BitRAT_K_2147833622_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BitRAT.K!MTB"
        threat_id = "2147833622"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 06 20 e8 03 00 00 73 ?? 00 00 0a 0d 08 09 08 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 08 09 08 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 08 17 6f}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 13 04 11 04 02 16 02 8e 69 6f ?? 00 00 0a 11 04 6f}  //weight: 2, accuracy: Low
        $x_1_3 = "GetMethod" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
        $x_1_5 = "GetResponseStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_BitRAT_L_2147834224_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BitRAT.L!MTB"
        threat_id = "2147834224"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a dc 02 6f ?? 00 00 0a 18 5b 8d ?? 00 00 01 0d 16 09 8e 69 28}  //weight: 2, accuracy: Low
        $x_1_2 = "GetType" ascii //weight: 1
        $x_1_3 = "GetMethod" ascii //weight: 1
        $x_1_4 = "GetResponse" ascii //weight: 1
        $x_1_5 = "get_UTF8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_BitRAT_R_2147837507_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BitRAT.R!MTB"
        threat_id = "2147837507"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {91 61 d2 6f 2d 00 11 ?? 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 06 11 ?? 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 06 8e 69 5d 91 7e ?? 00 00 04 11}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_BitRAT_I_2147844625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BitRAT.I!MTB"
        threat_id = "2147844625"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 08 06 6f ?? 00 00 0a 0d 07 09 6f ?? 00 00 0a 07 18 6f ?? 00 00 0a 02 13 04 07 6f ?? 00 00 0a 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 dd}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
        $x_1_6 = "ToList" ascii //weight: 1
        $x_1_7 = "get_CurrentDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_BitRAT_A_2147850680_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BitRAT.A!MTB"
        threat_id = "2147850680"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 04 06 91 20 92 ?? 00 00 59 d2 9c 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69 fe}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_BitRAT_Q_2147900537_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BitRAT.Q!MTB"
        threat_id = "2147900537"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 02 17 58 13 02}  //weight: 2, accuracy: High
        $x_2_2 = {02 8e 69 17 5b 8d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_BitRAT_P_2147900620_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BitRAT.P!MTB"
        threat_id = "2147900620"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bm90IGZvdW5kIGF0IHRoZSBzcGVjaWZpZWQgcGF0aC" wide //weight: 2
        $x_2_2 = "a2VybmVsMzIuZGxs" wide //weight: 2
        $x_2_3 = "SXNEZWJ1Z2dlclByZXNlbnQ=" wide //weight: 2
        $x_2_4 = "Q2hlY2tSZW1vdGVEZWJ1Z2dlclByZXNlbnQ=" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_BitRAT_B_2147902472_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BitRAT.B!MTB"
        threat_id = "2147902472"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "a2VybmVsMzIuZGxs" wide //weight: 2
        $x_2_2 = "SXNEZWJ1Z2dlclByZXNlbnQ=" wide //weight: 2
        $x_2_3 = "Q2hlY2tSZW1vdGVEZWJ1Z2dlclByZXNlbnQ=" wide //weight: 2
        $x_2_4 = "cG93ZXJzaGVsbC5leGU=" wide //weight: 2
        $x_2_5 = "LUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgQWRkLU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUGF0aC" wide //weight: 2
        $x_2_6 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_BitRAT_C_2147902609_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BitRAT.C!MTB"
        threat_id = "2147902609"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 11 01 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 2b 6f ?? 00 00 0a 26 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_BitRAT_T_2147905005_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BitRAT.T!MTB"
        threat_id = "2147905005"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 11 07 72 ?? ?? 00 70 28 ?? 00 00 0a 16 8d ?? 00 00 01 6f ?? 00 00 0a 26 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_BitRAT_U_2147905175_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BitRAT.U!MTB"
        threat_id = "2147905175"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 11 06 20 ?? ?? ?? 2c 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 06 26 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

