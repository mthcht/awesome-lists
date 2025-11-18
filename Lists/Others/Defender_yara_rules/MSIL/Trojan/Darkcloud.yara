rule Trojan_MSIL_Darkcloud_AAIZ_2147852445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcloud.AAIZ!MTB"
        threat_id = "2147852445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 06 8e 69 5d 06 07 06 8e 69 5d 91 09 07 1f 16 5d 6f ?? 00 00 0a 61 06 07 17 58 06 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 07 15 58 0b 07 16 fe 04 16 fe 01 13 06 11 06 2d bf}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcloud_AAKW_2147853236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcloud.AAKW!MTB"
        threat_id = "2147853236"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 07 11 07 6f ?? 00 00 0a 11 07 6f ?? 00 00 0a 28 ?? 00 00 06 13 08 20 03 00 00 00 38 ?? ff ff ff 11 07 02 7b ?? 00 00 04 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 20 01 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? ff ff ff 26}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcloud_AALE_2147888090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcloud.AALE!MTB"
        threat_id = "2147888090"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 8e 69 17 da 13 0f 16 13 10 2b 25 11 06 11 10 17 8d ?? 00 00 01 25 16 11 05 11 10 9a 1f 10 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 11 10 17 d6 13 10 11 10 11 0f 31 d5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcloud_AANT_2147889400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcloud.AANT!MTB"
        threat_id = "2147889400"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "03z72N1nPcl9MdEjsQo8b82fJ2ZAMAU21nA9yZsPGt4=" wide //weight: 1
        $x_1_2 = "0YTDLD6x/CycW4CG6bdhfw==" wide //weight: 1
        $x_1_3 = "$$$a$m$s$i$.$d$l$l$$$" wide //weight: 1
        $x_1_4 = "$$$A$ms$iSc$a$nBu$f$fer$$$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcloud_AAPC_2147891203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcloud.AAPC!MTB"
        threat_id = "2147891203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 05 73 ?? 00 00 0a 0b 07 11 04 11 05 6f ?? 00 00 0a 13 06 73 ?? 00 00 0a 0a 03 75 ?? 00 00 1b 73 ?? 00 00 0a 0c 08 11 06 16 73 ?? 00 00 0a 0d 09 06 6f ?? 00 00 0a 73 ?? 02 00 06 06 6f ?? 00 00 0a 28 ?? 02 00 06 de 1c 09 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcloud_AAZA_2147898684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcloud.AAZA!MTB"
        threat_id = "2147898684"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 28 19 00 00 0a 25 26 0b}  //weight: 2, accuracy: High
        $x_2_2 = {06 13 04 1a 2b b9 28 ?? 00 00 06 28 ?? 00 00 0a 0c 2b e8 26 1c 17 2d a7 26 11 04 0d 1e 16 2c 9f}  //weight: 2, accuracy: Low
        $x_2_3 = {06 25 26 20 00 01 00 00 14 14 09 28 ?? 00 00 06 6f ?? 00 00 0a 25 26 26}  //weight: 2, accuracy: Low
        $x_1_4 = "wfe1nQysLApikFgOFG.fxChPidY92AZW2bSGw" ascii //weight: 1
        $x_1_5 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcloud_AAJA_2147931092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcloud.AAJA!MTB"
        threat_id = "2147931092"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {01 25 16 0f 01 20 47 03 00 00 20 30 03 00 00 28 ?? 00 00 06 9c 25 17 0f 01 20 f1 00 00 00 20 89 00 00 00 28 ?? 00 00 06 9c 25 18 0f 01 20 39 01 00 00 20 40 01 00 00 28 ?? 00 00 06 9c 6f ?? 00 00 0a 16 0d}  //weight: 3, accuracy: Low
        $x_2_2 = {01 25 16 0f 00 20 4a 01 00 00 20 3d 01 00 00 28 ?? 00 00 06 9c 25 17 0f 00 20 8c 03 00 00 20 f4 03 00 00 28 ?? 00 00 06 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0a 17 0c 2b 8f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcloud_PGDC_2147954490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcloud.PGDC!MTB"
        threat_id = "2147954490"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 65 00 6e 00 65 00 72 00 67 00 79 00 74 00 75 00 6c 00 63 00 65 00 61 00 2e 00 72 00 6f 00 2f 00 [0-10] 2e 00 64 00 61 00 74 00}  //weight: 5, accuracy: Low
        $x_5_2 = {68 74 00 74 00 70 73 3a 2f 2f 65 6e 65 72 67 79 74 75 6c 63 65 61 2e 72 6f 2f [0-10] 2e 64 61 74}  //weight: 5, accuracy: Low
        $x_5_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 65 00 6e 00 65 00 72 00 67 00 79 00 74 00 75 00 6c 00 63 00 65 00 61 00 2e 00 72 00 6f 00 2f 00 [0-10] 2e 00 6d 00 70 00 34 00}  //weight: 5, accuracy: Low
        $x_5_4 = {68 74 00 74 00 70 73 3a 2f 2f 65 6e 65 72 67 79 74 75 6c 63 65 61 2e 72 6f 2f [0-10] 2e 6d 70 34}  //weight: 5, accuracy: Low
        $x_1_5 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "ComVisibleAttribute" ascii //weight: 1
        $x_1_8 = "DownloadData" ascii //weight: 1
        $x_1_9 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Darkcloud_ZSK_2147957680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcloud.ZSK!MTB"
        threat_id = "2147957680"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 07 08 6f ?? 00 00 0a 13 0a 03 06 6f ?? 00 00 0a 59 13 0b 11 0b 16 fe 02 16 fe 01 13 0f 11 0f 2c 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

