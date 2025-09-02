rule Trojan_MSIL_VenomRAT_FA_2147830952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VenomRAT.FA!MTB"
        threat_id = "2147830952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VenomRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "checkUAC" ascii //weight: 1
        $x_1_2 = "VenomRAT_HVNC" ascii //weight: 1
        $x_1_3 = "SOCKS5_AUTH_METHOD_GSSAPI" ascii //weight: 1
        $x_1_4 = "DownloadURL" ascii //weight: 1
        $x_1_5 = "get_HVNC_FrmURL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VenomRAT_B_2147907817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VenomRAT.B!MTB"
        threat_id = "2147907817"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VenomRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 06 25 0b 6f 16 00 04 28 ?? 00 00 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 0a 7e}  //weight: 2, accuracy: Low
        $x_2_2 = {03 8e 69 6f ?? 00 00 0a 0a 06 0b 09 00 04 6f ?? 00 00 0a 02 0e 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VenomRAT_SPFZ_2147914553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VenomRAT.SPFZ!MTB"
        threat_id = "2147914553"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VenomRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d2 13 32 11 18 1e 63 d1 13 18 11 16 11 0a 91 13 2a 11 16 11 0a 11 25 11 2a 61 19 11 1c 58 61 11 32 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VenomRAT_NV_2147914988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VenomRAT.NV!MTB"
        threat_id = "2147914988"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VenomRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {28 1d dc 00 06 72 ?? 58 18 70 7e ?? 18 00 04 6f ?? 00 00 0a 0a 06 74 ?? 00 00 1b 0b 2b 00}  //weight: 4, accuracy: Low
        $x_1_2 = "marketplace.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VenomRAT_SPDL_2147917960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VenomRAT.SPDL!MTB"
        threat_id = "2147917960"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VenomRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 08 11 05 08 5d 08 58 08 5d 13 09 07 11 09 91 11 06 61 11 08 59 20 00 02 00 00 58 13 0a 02 11 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VenomRAT_SPCB_2147928519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VenomRAT.SPCB!MTB"
        threat_id = "2147928519"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VenomRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 08 07 6f ?? 00 00 0a 17 73 0f 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0a de 0a 09 2c 06 09 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VenomRAT_SON_2147934103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VenomRAT.SON!MTB"
        threat_id = "2147934103"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VenomRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MeshEkran.Properties.Resources" wide //weight: 10
        $x_1_2 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_3 = "RijndaelManaged" ascii //weight: 1
        $x_1_4 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VenomRAT_SIS_2147936214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VenomRAT.SIS!MTB"
        threat_id = "2147936214"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VenomRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Venom RAT + HVNC + Stealer + Grabber.exe.licenses" ascii //weight: 2
        $x_2_2 = "VenomRATMutex_VenomRAT" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VenomRAT_EHLH_2147951131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VenomRAT.EHLH!MTB"
        threat_id = "2147951131"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VenomRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 11 04 8f 06 00 00 01 25 71 06 00 00 01 09 61 d2 81 06 00 00 01 11 04 17 58 13 04 11 04 06 8e 69 fe 04 13 ?? ?? ?? 2d d7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

