rule Trojan_MSIL_DuckTail_DB_2147851050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DuckTail.DB!MTB"
        threat_id = "2147851050"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DuckTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Telegram.Bot" ascii //weight: 1
        $x_1_2 = "chrome cookie " wide //weight: 1
        $x_1_3 = "firefox cookie " wide //weight: 1
        $x_1_4 = "Opera cookie" wide //weight: 1
        $x_1_5 = "Edge cookie " wide //weight: 1
        $x_1_6 = "facebook.com" wide //weight: 1
        $x_1_7 = "send cookie file" wide //weight: 1
        $x_1_8 = "Send telegram" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DuckTail_ADU_2147851631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DuckTail.ADU!MTB"
        threat_id = "2147851631"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DuckTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 16 13 05 38 ?? 00 00 00 11 04 11 05 9a 28 ?? 00 00 0a 13 06 11 06 72 ?? 01 00 70 6f ?? 00 00 0a 2d 0e 11 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DuckTail_ADU_2147851631_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DuckTail.ADU!MTB"
        threat_id = "2147851631"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DuckTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 2b 42 07 08 28 ?? ?? ?? 2b 1f 10 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 04 07 08 1f 10 58 28 ?? ?? ?? 2b 1f 10 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 05 11 04 11 05 73 1d 00 00 06 09 6f ?? ?? ?? 06 0d 08 1f 20 59 0c 08 16 2f ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DuckTail_ADT_2147890537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DuckTail.ADT!MTB"
        threat_id = "2147890537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DuckTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 0a 17 7e ?? 00 00 04 6f ?? ?? ?? 06 12 00 73 ?? 00 00 0a 0b 06 2d 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DuckTail_ATL_2147891190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DuckTail.ATL!MTB"
        threat_id = "2147891190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DuckTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 04 1f 0f 28 ?? 00 00 2b 04 8e 69 1f 10 59 1f 0f 59 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 04 04 8e 69 1f 10 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DuckTail_ADA_2147891196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DuckTail.ADA!MTB"
        threat_id = "2147891196"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DuckTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 05 0d 2b 42 07 08 28 ?? 00 00 2b 1f 10 28 ?? 00 00 2b 28 ?? 00 00 2b 13 04 07 08 1f 10 58 28 ?? 00 00 2b 1f 10 28 ?? 00 00 2b 28 ?? 00 00 2b 13 05 11 04 11 05 73 ?? 00 00 06 09 6f ?? 00 00 06 0d 08 1f 20 59 0c 08 16 2f ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DuckTail_ADI_2147891932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DuckTail.ADI!MTB"
        threat_id = "2147891932"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DuckTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 2b 31 09 11 04 9a 13 05 11 05 6f ?? 01 00 0a 72 ?? d8 00 70 6f ?? 00 00 0a 2c 0a 1f fd fe 1c 78 00 00 01 58 0b 11 04 1f fd fe 1c 78 00 00 01 58 58 13 04 11 04 09 8e 69 32 c8}  //weight: 2, accuracy: Low
        $x_1_2 = "fdoge_ChangeAccVIP.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

