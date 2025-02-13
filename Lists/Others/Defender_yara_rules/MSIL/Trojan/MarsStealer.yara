rule Trojan_MSIL_MarsStealer_MA_2147817202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MarsStealer.MA!MTB"
        threat_id = "2147817202"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MarsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 11 05 16 11 06 6f ?? ?? ?? 0a 00 00 09 11 05 16 11 04 6f ?? ?? ?? 0a 25 13 06 16 fe 03 13 08 11 08 2d db}  //weight: 1, accuracy: Low
        $x_1_2 = {13 05 16 13 06 73 ?? ?? ?? 0a 13 07 11 07 6f ?? ?? ?? 0a 16 2d d3}  //weight: 1, accuracy: Low
        $x_1_3 = "http://62.204.41.69" wide //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "MemoryStream" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MarsStealer_AAMF_2147888627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MarsStealer.AAMF!MTB"
        threat_id = "2147888627"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MarsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 16 07 1f 0f 1f 10 28 ?? 00 00 0a 06 07 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 1b 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 17 2c e8 09 04 16 04 8e 69 6f ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MarsStealer_AANY_2147889483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MarsStealer.AANY!MTB"
        threat_id = "2147889483"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MarsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 16 07 1f 0f 1f 10 28 ?? 00 00 0a 06 07 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 1b 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 09 04 16 04 8e 69 6f ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MarsStealer_AAQM_2147891970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MarsStealer.AAQM!MTB"
        threat_id = "2147891970"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MarsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {04 06 18 28 ?? 01 00 06 7e ?? 01 00 04 06 1b 28 ?? 01 00 06 7e ?? 01 00 04 06 28 ?? 01 00 06 0d 7e ?? 01 00 04 09 03 16 03 8e 69 28 ?? 01 00 06 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MarsStealer_AAWE_2147895926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MarsStealer.AAWE!MTB"
        threat_id = "2147895926"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MarsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 21 45 00 70 28 ?? 00 00 0a 00 72 39 45 00 70 28 ?? 00 00 0a 61 69}  //weight: 2, accuracy: Low
        $x_2_2 = {72 55 45 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 5b 59 7e ?? 00 00 0a 8e 59 7e ?? 00 00 0a 8e 59 28 ?? 00 00 06 7e ?? 00 00 04 7e ?? 00 00 04 28 ?? 00 00 06 28 ?? 00 00 06 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

