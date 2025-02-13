rule Trojan_MSIL_Ursu_AUR_2147831864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ursu.AUR!MTB"
        threat_id = "2147831864"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ursu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 13 07 11 09 11 07 1f 2a 61 d1 13 07 fe 0d 07 00 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ursu_AUR_2147831864_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ursu.AUR!MTB"
        threat_id = "2147831864"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ursu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {17 59 0c 17 0d 2b 2d 17 13 04 2b 1f 02 11 04 09 6f ?? ?? ?? 0a 13 05 06 12 05 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 11 04 17 58 13 04 11 04 07 31 dc}  //weight: 2, accuracy: Low
        $x_1_2 = "testSt.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ursu_AUR_2147831864_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ursu.AUR!MTB"
        threat_id = "2147831864"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ursu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 16 72 1b 00 00 70 a2 06 17 28 ?? 00 00 06 a2 06 18 72 5f 00 00 70 a2 06 19 28 ?? 00 00 06 a2 06 1a 72 77 00 00 70 a2 06 1b 28 ?? 00 00 06 a2 06 1c 72 83 00 00 70 a2 06 1d 28}  //weight: 1, accuracy: Low
        $x_1_2 = {0b 07 16 72 fb 00 00 70 a2 07 17 7e 01 00 00 04 a2 07 18 72 35 01 00 70 a2 07 19 7e 02 00 00 04 a2 07 1a 72 61 01 00 70 a2 07 1b 02 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ursu_AU_2147843421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ursu.AU!MTB"
        threat_id = "2147843421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ursu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0a 06 2d 15 7e 12 00 00 0a 02 6f ?? ?? ?? 0a 03 04 1a 6f ?? ?? ?? 0a de 24 06 03 6f ?? ?? ?? 0a 04 2e 09 06 03 04 1a 6f ?? ?? ?? 0a de 0a 06 2c 06 06 6f ?? ?? ?? 0a dc de 03 26 de 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ursu_AU_2147843421_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ursu.AU!MTB"
        threat_id = "2147843421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ursu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 17 12 00 15 6a 16 28 ?? ?? ?? 0a 17 8d 0c 00 00 01 0d 09 16 17 9e 09 28 ?? ?? ?? 0a 06 72 e9 00 00 70 15 16 28 ?? ?? ?? 0a 0b 19 08}  //weight: 2, accuracy: Low
        $x_1_2 = "bin.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ursu_A_2147896064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ursu.A!MTB"
        threat_id = "2147896064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ursu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {26 20 84 79 20 71 20 e9 23 76 19 61 25 fe 0e 01 00 20 0a ?? ?? ?? 5e}  //weight: 10, accuracy: Low
        $x_3_2 = "Giantmaster" ascii //weight: 3
        $x_3_3 = "Thousandinto" ascii //weight: 3
        $x_3_4 = "Jobdifference" ascii //weight: 3
        $x_3_5 = "GrewAsk" ascii //weight: 3
        $x_3_6 = "Seeingsheet" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Ursu_AMBA_2147896640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ursu.AMBA!MTB"
        threat_id = "2147896640"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ursu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 02 50 28 ?? 00 00 06 02 50 8e 69 28 ?? 00 00 06 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ursu_ARA_2147899497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ursu.ARA!MTB"
        threat_id = "2147899497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ursu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 02 08 91 08 58 06 08 91 58 d2 9c 08 17 58 0c 08 07 8e 69 32 e9 07 28 0b 01 00 0a}  //weight: 2, accuracy: High
        $x_2_2 = "FuckAV" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ursu_KAA_2147901608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ursu.KAA!MTB"
        threat_id = "2147901608"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ursu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 69 95 61 d2 9c 11 ?? 17 58 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ursu_SWA_2147931287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ursu.SWA!MTB"
        threat_id = "2147931287"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ursu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 28 02 00 00 0a 0a 08 06 16 06 8e b7 6f ?? 00 00 0a 00 08 6f ?? 00 00 0a 00 28 ?? 00 00 0a 09 6f ?? 00 00 0a 6f ?? 00 00 0a 10 00 de 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

