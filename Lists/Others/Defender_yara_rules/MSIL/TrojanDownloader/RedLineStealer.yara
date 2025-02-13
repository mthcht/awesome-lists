rule TrojanDownloader_MSIL_RedLineStealer_KA_2147818437_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLineStealer.KA!MTB"
        threat_id = "2147818437"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 8e 69 28 ?? ?? ?? 0a 00 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 26 00 2a 26 00 7e ?? ?? ?? 04 16 7e}  //weight: 1, accuracy: Low
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "GetResponse" ascii //weight: 1
        $x_1_4 = "ReadBytes" ascii //weight: 1
        $x_1_5 = "WebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLineStealer_KB_2147818438_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLineStealer.KB!MTB"
        threat_id = "2147818438"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 08 6f ?? ?? ?? 0a 00 16 2d ?? 06 08 6f ?? ?? ?? 0a 16 08 6f ?? ?? ?? 0a 8e 69 6f ?? ?? ?? 0a 00 06 0d 46 00 72 ?? ?? ?? 70 2b ?? 2b ?? 2b ?? 2b ?? 20 ?? ?? ?? 05 2b ?? 2b ?? 73 ?? ?? ?? 0a 0c 08 07 6f}  //weight: 1, accuracy: Low
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "GetResponse" ascii //weight: 1
        $x_1_4 = "ReadBytes" ascii //weight: 1
        $x_1_5 = "WebRequest" ascii //weight: 1
        $x_1_6 = "WebResponse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLineStealer_KF_2147818581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLineStealer.KF!MTB"
        threat_id = "2147818581"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 28 01 00 00 2b 28 02 00 00 2b [0-21] 28 ?? ?? ?? 0a 38 ?? ?? ?? ff 6f ?? ?? ?? 0a 38 ?? ?? ?? ff 6f ?? ?? ?? 0a 38 ?? ?? ?? ff 73 ?? ?? ?? 0a 38 ?? ?? ?? ff 6f ?? ?? ?? 0a 38 ?? ?? ?? ff 0a 38}  //weight: 1, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "BinaryReader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLineStealer_KH_2147826059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLineStealer.KH!MTB"
        threat_id = "2147826059"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 61 65 20 f0 a7 2a 21 58 20 ?? ?? ?? d9 61 59 25 fe ?? ?? 00 20 ?? ?? ?? b4 20 ?? ?? ?? 11 58 20 ?? ?? ?? 17 61 20 ?? ?? ?? f1 58 20 ?? ?? ?? e3 61 20 ?? ?? ?? d8 58 20 ?? ?? ?? 11 58 20 ?? ?? ?? 11 61 3c ?? ?? ?? ff 8d 00 fe ?? ?? 00 93 20 ?? ?? ?? e0 20 ?? ?? ?? e6 58 20 ?? ?? ?? e5 61 20 ?? ?? ?? 23 59 61 fe ?? ?? 00 61 d1 9d fe ?? ?? 00 20 ?? ?? ?? 1a 20 ?? ?? ?? 11 58 20 ?? ?? ?? fb 61 65 20 ?? ?? ?? 27 58 20}  //weight: 1, accuracy: Low
        $x_1_2 = {10 58 65 20 ?? ?? ?? 04 59 65 9d 6f ?? ?? ?? 0a fe ?? ?? 00 38 67 00 28 ?? ?? ?? 0a fe ?? ?? 00 6f ?? ?? ?? 0a 20 ?? ?? ?? ff 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 62 20 ?? ?? ?? 00 63 8d ?? ?? ?? 01 25 20 ?? ?? ?? 03 65 20 ?? ?? ?? fc 59 20 ?? ?? ?? 00 63 20 ?? ?? ?? 00 62 20 ?? ?? ?? eb 65 66 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLineStealer_KI_2147826060_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLineStealer.KI!MTB"
        threat_id = "2147826060"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 07 9e 00 07 17 58 0b 07 20 1e 00 11 ?? 07 02 07 02 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 9e 11}  //weight: 1, accuracy: Low
        $x_1_2 = {07 94 58 20 ?? ?? ?? 00 5d 0c 11 ?? 07 94 13 ?? 11 ?? 07 11 ?? 08 94 9e 11 ?? 08 11 ?? 9e ?? 07 17 58 0b 07 20 2d 00 08 11 ?? 07 94 58 11}  //weight: 1, accuracy: Low
        $x_1_3 = {06 17 58 0a 06 20 ?? ?? ?? 00 5d 0a 08 11 ?? 06 94 58 0c 08 20 ?? ?? ?? 00 5d 0c 11 ?? 06 94 13 ?? 11 ?? 06 11 ?? 08 94 9e 11 ?? 08 11 ?? 9e 11 ?? 11 ?? 06 94 11 ?? 08 94 58 20 ?? ?? ?? 00 5d 94 0d 11 ?? 07 03 07 91 09 61 d2 9c ?? 07 17 58 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLineStealer_KL_2147831486_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLineStealer.KL!MTB"
        threat_id = "2147831486"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 20 00 01 00 00 6f ?? 00 00 0a 07 20 80 00 00 00 6f ?? 00 00 0a 28 ?? 00 00 0a 72 ?? ?? ?? 70 6f ?? 00 00 0a 7e ?? 00 00 04 20 e8 03 00 00 73 ?? 00 00 0a 0c 07 08 07 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 07 08 07 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 07 17 6f ?? 00 00 0a 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0d 09 02 16 02 8e 69 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLineStealer_KO_2147834516_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLineStealer.KO!MTB"
        threat_id = "2147834516"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 06 07 72 6f ?? 00 70 17 72 3d ?? 00 70 6f ?? 00 00 06 6f ?? 00 00 06 7d ?? 00 00 04 02 06 07 72 e5 ?? 00 70 17 72 5d ?? 00 70 6f ?? 00 00 06 6f ?? 00 00 06 7d ?? 00 00 04 06 17 1f 64 6a 1f 14 6a 16 6a 6f ?? 00 00 06 0c 08 2c 31 00 06 02 7b}  //weight: 2, accuracy: Low
        $x_1_2 = "GetType" wide //weight: 1
        $x_1_3 = "GetMethod" wide //weight: 1
        $x_1_4 = "Invoke" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLineStealer_KR_2147839639_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLineStealer.KR!MTB"
        threat_id = "2147839639"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8e 69 5d 91 7e ?? 00 00 04 fe ?? ?? 00 91 61 d2 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "GetDomain" ascii //weight: 1
        $x_1_3 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLineStealer_KT_2147840692_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLineStealer.KT!MTB"
        threat_id = "2147840692"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 06 8e 69 5d 91 fe ?? ?? 00 fe ?? ?? 00 91 61 d2 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLineStealer_KU_2147842676_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLineStealer.KU!MTB"
        threat_id = "2147842676"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 8e 69 5d 91 07 11 ?? 91 61 d2 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "GetMethods" ascii //weight: 1
        $x_1_3 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLineStealer_KD_2147844619_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLineStealer.KD!MTB"
        threat_id = "2147844619"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 9a 0d 09 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 0a 13 04 11 04 2c}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 0a 13 05 11 05 72 ?? 00 00 70 6f ?? 00 00 0a 13 06 11 06 14 14 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLineStealer_KN_2147844639_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLineStealer.KN!MTB"
        threat_id = "2147844639"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 12 01 28 ?? 00 00 0a 7e ?? 00 00 04 02 28 ?? 00 00 0a 0c 08 7e ?? 00 00 04 6f ?? 00 00 0a 3c ?? 00 00 00 7e ?? 00 00 04 08 6f ?? 00 00 0a 02 40 ?? 00 00 00 7e ?? 00 00 04 08 6f ?? 00 00 0a 0d dd}  //weight: 2, accuracy: Low
        $x_2_2 = {01 13 04 7e 05 00 00 04 02 1a 58 11 04 16 08 28 1c 00 00 0a 28 18 00 00 0a 11 04 16 11 04 8e 69 6f 5f 00 00 0a 13 05 7e 04 00 00 04 11 05 6f 60 00 00 0a 7e 2b 00 00 04 02 6f 61 00 00 0a 7e 04 00 00 04 6f 62 00 00 0a 17 59 28 63 00 00 0a 16 7e 05 00 00 04 02 1a 28 1c 00 00 0a 11 05 0d dd}  //weight: 2, accuracy: High
        $x_1_3 = "WebClient" ascii //weight: 1
        $x_1_4 = "Process" ascii //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLineStealer_KP_2147850693_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLineStealer.KP!MTB"
        threat_id = "2147850693"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 02 18 58 13 02 38}  //weight: 2, accuracy: High
        $x_2_2 = {11 00 18 5b 8d ?? 00 00 01 13 01}  //weight: 2, accuracy: Low
        $x_2_3 = {11 01 11 02 18 5b 02 11 02 18 6f ?? 00 00 0a 1f 10 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLineStealer_KC_2147900123_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLineStealer.KC!MTB"
        threat_id = "2147900123"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 91 72 ?? 00 00 70 28 ?? 00 00 ?? 59 d2 9c 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLineStealer_KM_2147900523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLineStealer.KM!MTB"
        threat_id = "2147900523"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {59 17 59 91 9c}  //weight: 2, accuracy: High
        $x_2_2 = {59 17 59 11 05 9c}  //weight: 2, accuracy: High
        $x_2_3 = {11 03 17 58 13 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLineStealer_KX_2147904770_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLineStealer.KX!MTB"
        threat_id = "2147904770"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 0c 08 6f ?? ?? ?? 0a 20 00 01 00 00 14 14 14 6f ?? ?? ?? 0a 26}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLineStealer_KY_2147915830_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLineStealer.KY!MTB"
        threat_id = "2147915830"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 8e 0c 08 8d ?? ?? ?? 01 0b 16 0a 16 08 2f ?? 07 06 03 06 03 8e 5d 91 02 06 91 61 9c 06 17 58 0a 06 02 8e 32}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

