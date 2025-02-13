rule TrojanDownloader_MSIL_FormBook_AE_2147817762_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/FormBook.AE!MTB"
        threat_id = "2147817762"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$61989da5-0365-4521-9196-6e945b8a9868" ascii //weight: 1
        $x_1_2 = "YUEWUYDSHJDS65325.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "GetResponseStream" ascii //weight: 1
        $x_1_5 = "InvokeMember" ascii //weight: 1
        $x_1_6 = "RRUUNNN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_FormBook_NYH_2147828381_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/FormBook.NYH!MTB"
        threat_id = "2147828381"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 07 8e 69 5d 91 06 09 91 61 d2 6f ?? 00 00 0a 09 17 58 0d 09 06 8e 69 32 e3}  //weight: 1, accuracy: Low
        $x_1_2 = "PO_20220280896582" ascii //weight: 1
        $x_1_3 = {15 b6 09 09 0b 00 00 00 10 00 01 00 02 00 00 01 00 00 00 30 00 00 00 08 00 00 00 08 00 00 00 19 00 00 00 0f 00 00 00 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_FormBook_NYI_2147828705_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/FormBook.NYI!MTB"
        threat_id = "2147828705"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 08 11 04 08 8e 69 5d 91 06 11 04 91 61 d2}  //weight: 1, accuracy: High
        $x_1_2 = {95 b6 29 09 0b 00 00 00 da a4 21 00 16 00 00 01 00 00 00 35 00 00 00 08 00 00 00 07 00 00 00 14 00 00 00 0a 00 00 00 3f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_FormBook_ABL_2147830994_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/FormBook.ABL!MTB"
        threat_id = "2147830994"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {1e 5b 6f 12 ?? ?? 0a 6f ?? ?? ?? 0a 07 17 6f ?? ?? ?? 0a 06 07 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0d 16 2d ef 2b 03 0c 2b bb 09 02 16 02 8e 69 6f ?? ?? ?? 0a de 07 09 6f ?? ?? ?? 0a dc 06 6f ?? ?? ?? 0a 13 04 de 4c}  //weight: 3, accuracy: Low
        $x_3_2 = {08 2b dc 6f ?? ?? ?? 0a 2b d7 07 2b d6}  //weight: 3, accuracy: Low
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "Rfc2898DeriveBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_FormBook_ABO_2147831439_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/FormBook.ABO!MTB"
        threat_id = "2147831439"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 08 07 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 17 6f ?? ?? ?? 0a 06 07 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0d 16 2d 0e 16 2d 0b 09 02 16 02 8e 69 6f ?? ?? ?? 0a de 0d 1d 2c 03 09 2c 06 09 6f ?? ?? ?? 0a dc 06 6f ?? ?? ?? 0a 13 04 16}  //weight: 4, accuracy: Low
        $x_3_2 = {08 2b df 6f ?? ?? ?? 0a 2b da 08 2b dc 6f ?? ?? ?? 0a 2b d7}  //weight: 3, accuracy: Low
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "Rfc2898DeriveBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_FormBook_A_2147900583_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/FormBook.A!MTB"
        threat_id = "2147900583"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0d 08 09 16 73 ?? 00 00 0a 13 04 11 04 02 7b ?? 00 00 04 6f ?? 00 00 0a 02 7b ?? 00 00 04 6f ?? 00 00 0a 13 05 dd}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_FormBook_B_2147900843_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/FormBook.B!MTB"
        threat_id = "2147900843"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 13 04 73 ?? 00 00 0a 13 05 08 73 ?? 00 00 0a 13 06 11 06 11 04 16 73 ?? 00 00 0a 13 07 11 07 11 05 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 08 de}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_FormBook_C_2147900925_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/FormBook.C!MTB"
        threat_id = "2147900925"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1b 11 06 16 16 02 17 8d ?? 00 00 01 25 16 11 06 8c ?? 00 00 01 a2 14 28}  //weight: 2, accuracy: Low
        $x_2_2 = {01 20 10 27 00 00 6f ?? 00 00 0a 07 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_FormBook_D_2147900930_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/FormBook.D!MTB"
        threat_id = "2147900930"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 20 00 01 00 00 14 14 14 6f ?? 00 00 0a 26 20}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_FormBook_F_2147904551_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/FormBook.F!MTB"
        threat_id = "2147904551"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 11 00 11 02 11 00 91 20}  //weight: 2, accuracy: High
        $x_2_2 = {06 59 d2 9c 20}  //weight: 2, accuracy: High
        $x_2_3 = {02 16 25 13 01 7d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_FormBook_G_2147905286_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/FormBook.G!MTB"
        threat_id = "2147905286"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 0b 07 8e 69 0c 2b ?? 06 07 08 91 6f ?? 00 00 0a 08 25 17 59 0c 16 fe ?? 2d ?? 06 6f ?? 00 00 0a 0b 07 0d 09}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_FormBook_H_2147905287_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/FormBook.H!MTB"
        threat_id = "2147905287"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0b 06 8e 69 0c 2b ?? 07 06 08 91 6f ?? 00 00 0a 08 25 17 59 0c 16 fe ?? 2d ?? 07 6f ?? 00 00 0a 0a 06 0d 09 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

