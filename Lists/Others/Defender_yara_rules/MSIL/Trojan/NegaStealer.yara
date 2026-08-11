rule Trojan_MSIL_NegaStealer_RPZ_2147842427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NegaStealer.RPZ!MTB"
        threat_id = "2147842427"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NegaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kosmikband.com" wide //weight: 1
        $x_1_2 = "wtrash" wide //weight: 1
        $x_1_3 = "Rcegjxdrgak.png" wide //weight: 1
        $x_1_4 = "GetxType" wide //weight: 1
        $x_1_5 = "Loxad" wide //weight: 1
        $x_1_6 = "Invxoke" wide //weight: 1
        $x_1_7 = "GetMetxhod" wide //weight: 1
        $x_1_8 = "GZipStream" ascii //weight: 1
        $x_1_9 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NegaStealer_AULB_2147958154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NegaStealer.AULB!MTB"
        threat_id = "2147958154"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NegaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 05 11 06 6f ?? 00 00 0a 13 07 03 11 04 6f ?? 00 00 0a 59 13 08 11 04 17 8d ?? 00 00 01 25 16 11 07 72 ?? ?? 00 70 28 ?? 00 00 06 9c 6f ?? 00 00 0a 11 08 17 59 25 13 08 16 3e ?? 00 00 00 11 04 17 8d ?? 00 00 01 25 16 11 07 72 ?? ?? 00 70 28 ?? 00 00 06 9c 6f ?? 00 00 0a 11 08 17 59 25 13 08 16 3e ?? 00 00 00 11 04 17 8d ?? 00 00 01 25 16 11 07 72 ?? ?? 00 70 28 ?? 00 00 06 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NegaStealer_ABSG_2147975945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NegaStealer.ABSG!MTB"
        threat_id = "2147975945"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NegaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 05 11 05 2c 26 00 03 03 7b ?? 00 00 04 03 7b ?? 00 00 04 03 7b ?? 00 00 04 6f ?? 00 00 0a 7d ?? 00 00 04 03 17 7d ?? 00 00 04 00 12 01 fe ?? ?? ?? ?? ?? 12 01 17 7d ?? 00 00 04 07 0c 2b 08 17 13 06}  //weight: 5, accuracy: Low
        $x_5_2 = {25 16 72 ae 06 00 70 a2 25 17 72 b2 06 00 70 a2 25 18 72 b6 06 00 70 a2 25 19 72 7a 06 00 70 a2 25 1a 72 c8 05 00 70 a2 25 1b 72 a6 05 00 70 a2 0c 16 0d 2b 77}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

