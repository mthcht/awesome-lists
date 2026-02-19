rule Trojan_MSIL_PhantomStealer_APH_2147955276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhantomStealer.APH!MTB"
        threat_id = "2147955276"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhantomStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 02 7d ?? 00 00 04 00 06 7b ?? 00 00 04 14 fe 01 13 0c 11 0c 2c 05 38 ?? 00 00 00 06 7b ?? 00 00 04 6f ?? 00 00 0a 0b 06 06 7b ?? 00 00 04 6f ?? 00 00 0a 7d ?? 00 00 04 07 06 7b ?? 00 00 04 5a 19 5a 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PhantomStealer_APN_2147955823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhantomStealer.APN!MTB"
        threat_id = "2147955823"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhantomStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 08 11 1b 11 19 1d 5d 1f 1f 5f 62 11 19 1f 61 5a 61 61 13 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PhantomStealer_GPA_2147957226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhantomStealer.GPA!MTB"
        threat_id = "2147957226"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhantomStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QBXtX" ascii //weight: 1
        $x_1_2 = "startupreg" ascii //weight: 1
        $x_1_3 = "caminhovbs" ascii //weight: 1
        $x_1_4 = "namevbs" ascii //weight: 1
        $x_1_5 = "netframework" ascii //weight: 1
        $x_1_6 = "nativo" ascii //weight: 1
        $x_1_7 = "nomenativo" ascii //weight: 1
        $x_1_8 = "persitencia" ascii //weight: 1
        $x_1_9 = "caminho" ascii //weight: 1
        $x_1_10 = "nomedoarquivo" ascii //weight: 1
        $x_1_11 = "minutos" ascii //weight: 1
        $x_1_12 = "taskname" ascii //weight: 1
        $x_1_13 = "vmName" ascii //weight: 1
        $x_1_14 = "url_uac" ascii //weight: 1
        $x_1_15 = "comanduac" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PhantomStealer_ATPB_2147962077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhantomStealer.ATPB!MTB"
        threat_id = "2147962077"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhantomStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0f 06 7b ?? 00 00 04 11 0a 11 0e 6f ?? 00 00 0a 7d ?? 00 00 04 11 06 17 58 13 06 11 0f 7c ?? 00 00 04 28 ?? 00 00 0a 6c 23 89 41 60 e5 d0 22 d3 3f 5a 11 0f 7c ?? 00 00 04 28 ?? 00 00 0a 6c 23 62 10 58 39 b4 c8 e2 3f 5a 58 11 0f 7c ?? 00 00 04 28 ?? 00 00 0a 6c 23 c9 76 be 9f 1a 2f bd 3f 5a 58 13 10 11 10 23 00 00 00 00 00 00 60 40 fe 02 13 11 06 7b ?? 00 00 04 6f ?? 00 00 0a 03 fe 04 13 13 11 13 2c 18 06 7b ?? 00 00 04 11 0f 7c ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 7b ?? 00 00 04 6f ?? 00 00 0a 03 fe 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PhantomStealer_AUQB_2147963319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhantomStealer.AUQB!MTB"
        threat_id = "2147963319"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhantomStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 09 11 0a 6f ?? 00 00 0a 13 0c 12 0c 28 ?? 00 00 0a 13 0d 12 0c 28 ?? 00 00 0a 13 0e 12 0c 28 ?? 00 00 0a 13 0f 11 0d 28 ?? 00 00 06 13 10 11 0e 28 ?? 00 00 06 13 11 11 0f 28 ?? 00 00 06 13 12 11 10 11 11 5f 11 12 5f}  //weight: 5, accuracy: Low
        $x_2_2 = {11 0d 1b 62 11 0d 19 63 60 d2 13 0d 11 0d 1b 63 11 0d 19 62 60 d2 13 0d 11 0e 20 f3 00 00 00 58 20 ff 00 00 00 5f d2 13 0e 11 0e 20 f3 00 00 00 59 20 ff 00 00 00 5f d2 13 0e 11 0f 20 c8 00 00 00 61 d2 13 0f 11 0f 20 c8 00 00 00 61 d2 13 0f 11 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

