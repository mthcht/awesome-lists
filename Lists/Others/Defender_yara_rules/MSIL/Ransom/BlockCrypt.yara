rule Ransom_MSIL_BlockCrypt_PB_2147795315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BlockCrypt.PB!MTB"
        threat_id = "2147795315"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlockCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/C net view" wide //weight: 1
        $x_2_2 = {07 08 03 08 91 04 61 d2 9c 08 17 58 0c 08 03 8e 69 fe 04 0d 09 2d e9}  //weight: 2, accuracy: High
        $x_2_3 = {07 08 07 08 93 ?? 61 d1 9d 06 07 08 93 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0a 00 08 17 58 0c 08 07 8e 69 fe ?? 0d 09 2d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_BlockCrypt_PD_2147798748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BlockCrypt.PD!MTB"
        threat_id = "2147798748"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlockCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Encrypt" ascii //weight: 1
        $x_1_2 = "DownloadFile" ascii //weight: 1
        $x_1_3 = "wall.jpg" wide //weight: 1
        $x_1_4 = "s.bat" wide //weight: 1
        $x_1_5 = "st.bat" wide //weight: 1
        $x_1_6 = {52 00 65 00 61 00 64 00 4d 00 65 00 21 00 [0-16] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

