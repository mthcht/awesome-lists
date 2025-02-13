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

