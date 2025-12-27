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

