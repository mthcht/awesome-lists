rule Trojan_MSIL_TeslaCrypt_VN_2147758684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TeslaCrypt.VN!MTB"
        threat_id = "2147758684"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 5d 91 61 d2 81 0e 00 00 01 00 07 17 13 ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 40 ?? ?? ?? 00 20 ?? ?? ?? 00 13 ?? 20 ?? ?? ?? ?? 58 00 58 0b 07 02 8e 69 fe ?? 0d 09 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_TeslaCrypt_VN_2147758684_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TeslaCrypt.VN!MTB"
        threat_id = "2147758684"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 20 00 2b ?? 00 20 ?? ?? ?? 00 13 20 00 02 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 13 21 73 ?? ?? ?? 06 13 22 19 8d ?? ?? ?? 01 80 ?? ?? ?? 04 7e ?? ?? ?? 04 16 7e ?? ?? ?? 04 a2 7e ?? ?? ?? 04 17 7e ?? ?? ?? 04 a2 02 11 21 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 28 ?? ?? ?? 06 26 06}  //weight: 1, accuracy: Low
        $x_1_2 = {01 0a 19 8d ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 a2 25 17 7e ?? ?? ?? 04 a2 25 18 7e ?? ?? ?? 04 a2 0a 06 28 ?? ?? ?? 0a [0-64] 73 ?? ?? ?? 06 0b 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_TeslaCrypt_IN_2147760998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TeslaCrypt.IN!MTB"
        threat_id = "2147760998"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CompressionMode" ascii //weight: 1
        $x_1_2 = "BitConverter" ascii //weight: 1
        $x_1_3 = "ToInt32" ascii //weight: 1
        $x_1_4 = "GetPixel" ascii //weight: 1
        $x_1_5 = "get_R" ascii //weight: 1
        $x_1_6 = "get_G" ascii //weight: 1
        $x_1_7 = "get_B" ascii //weight: 1
        $x_1_8 = "ResourceManager" ascii //weight: 1
        $x_1_9 = "ToArray" ascii //weight: 1
        $x_1_10 = "Sleep" ascii //weight: 1
        $x_1_11 = "System.Threading" ascii //weight: 1
        $x_1_12 = "MethodBase" ascii //weight: 1
        $x_1_13 = "Invoke" ascii //weight: 1
        $x_1_14 = "never let yourself be defeated" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_TeslaCrypt_IP_2147760999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TeslaCrypt.IP!MTB"
        threat_id = "2147760999"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetPixel" ascii //weight: 1
        $x_1_2 = "FromArgb" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "GZipStream" ascii //weight: 1
        $x_1_5 = "System.IO.Compression" ascii //weight: 1
        $x_1_6 = "BitConverter" ascii //weight: 1
        $x_1_7 = "GetEntryAssembly" ascii //weight: 1
        $x_7_8 = "You will face many defeats in life, but never let yourself be defeated." wide //weight: 7
        $x_7_9 = "Sparta.dll" wide //weight: 7
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_7_*) and 7 of ($x_1_*))) or
            ((2 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_TeslaCrypt_A_2147761081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TeslaCrypt.A!MTB"
        threat_id = "2147761081"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tetris.My" ascii //weight: 1
        $x_1_2 = "ToCharArray" ascii //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_TeslaCrypt_C_2147761916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TeslaCrypt.C!MTB"
        threat_id = "2147761916"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Aphrodite.dll" ascii //weight: 1
        $x_1_2 = "Friedrich" ascii //weight: 1
        $x_1_3 = {73 65 74 5f 4b 65 79 00 73 65 74 5f 49 56 00 43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 00 57 72 69 74 65 00 43 6c 6f 73 65 00 54 6f 41 72 72 61 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_TeslaCrypt_D_2147761917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TeslaCrypt.D!MTB"
        threat_id = "2147761917"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 65 78 74 00 53 6c 65 65 70 00 49 6e 76 6f 6b 65 4d 65 6d 62 65 72}  //weight: 1, accuracy: High
        $x_1_2 = "projname" ascii //weight: 1
        $x_1_3 = "GODofBeauty" ascii //weight: 1
        $x_1_4 = "Aphrodite.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

