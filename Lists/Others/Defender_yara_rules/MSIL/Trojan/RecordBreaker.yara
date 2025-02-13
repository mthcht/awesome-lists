rule Trojan_MSIL_RecordBreaker_RDA_2147835124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RecordBreaker.RDA!MTB"
        threat_id = "2147835124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kernel32" ascii //weight: 1
        $x_1_2 = "LoadLibraryA" ascii //weight: 1
        $x_1_3 = "GetProcAddress" ascii //weight: 1
        $x_1_4 = "Oracle Corporation" ascii //weight: 1
        $x_1_5 = "Java Platform SE 8 U351" ascii //weight: 1
        $x_2_6 = {11 07 07 03 07 91 09 61 d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RecordBreaker_RDC_2147836250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RecordBreaker.RDC!MTB"
        threat_id = "2147836250"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "07193d46-2bc0-4413-a42b-0739d005f63a" ascii //weight: 1
        $x_2_2 = {e0 4a fe 0c 04 00 fe ?? ?? ?? 20 01 00 00 00 59 8f ?? ?? ?? ?? e0 4a 61 54 fe ?? ?? ?? fe ?? ?? ?? 20 02 00 00 00 59 20 00 00 00 00 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RecordBreaker_A_2147838238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RecordBreaker.A!MTB"
        threat_id = "2147838238"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 09 04 59 d1 6f ?? 00 00 0a 26}  //weight: 2, accuracy: Low
        $x_2_2 = {08 17 58 0c}  //weight: 2, accuracy: High
        $x_2_3 = {08 07 8e 69}  //weight: 2, accuracy: High
        $x_2_4 = {20 e8 03 00 00 28 ?? 00 00 0a 06 17 58 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RecordBreaker_RDE_2147842953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RecordBreaker.RDE!MTB"
        threat_id = "2147842953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fe 0c 1f 00 fe 0c 17 00 46 fe 0c 03 00 61 52 fe 0c 17 00 20 01 00 00 00 58 fe 0e 17 00 fe 0c 1f 00 20 01 00 00 00 58 fe 0e 1f 00}  //weight: 2, accuracy: High
        $x_1_2 = "LoadLibraryW" ascii //weight: 1
        $x_1_3 = "GetProcAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RecordBreaker_RDH_2147896725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RecordBreaker.RDH!MTB"
        threat_id = "2147896725"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {e0 4a 61 54 fe 0c 01 00 fe 0c 00 00 20 02 00 00 00 59 20 00 00 00 00 9c fe 0c 00 00 20 01 00 00 00 59 fe 0e 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RecordBreaker_TWAA_2147918430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RecordBreaker.TWAA!MTB"
        threat_id = "2147918430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 72 01 00 00 70 28 ?? 00 00 06 72 33 00 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 13 0b}  //weight: 2, accuracy: Low
        $x_2_2 = {09 11 0a 28 ?? 00 00 2b 16 11 0a 28 ?? 00 00 2b 8e 69 6f ?? 00 00 0a 16}  //weight: 2, accuracy: Low
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RecordBreaker_RDM_2147921740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RecordBreaker.RDM!MTB"
        threat_id = "2147921740"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 32 00 00 0a a2 25 18 18 8c 49 00 00 01 a2 25 19 17 8d 17 00 00 01 25 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RecordBreaker_NIT_2147923669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RecordBreaker.NIT!MTB"
        threat_id = "2147923669"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 9f 72 ee 2e 01 70 72 35 31 01 70 72 3b 31 01 70 28 ?? 00 00 0a 72 3d 31 01 70 72 a5 31 01 70 14 28 ?? 00 00 0a 28 ?? 00 00 0a 7e 31 00 00 0a 6f 32 00 00 0a 13 a0 1c 11 6c 28 ?? 00 00 0a 72 a9 31 01 70 28 ?? 00 00 0a 28 ?? 00 00 0a 12 a0 28 ?? 00 00 06 26 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {72 0b 21 01 70 7e 31 00 00 0a 28 ?? 00 00 0a 72 13 21 01 70 72 19 21 01 70 72 1d 21 01 70 28 ?? 00 00 0a 72 21 21 01 70 72 25 21 01 70 6f ?? 00 00 0a 72 29 21 01 70 72 3d 21 01 70 72 4f 21 01 70 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 13 a1 12 a1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

