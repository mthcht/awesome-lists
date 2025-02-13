rule Trojan_MSIL_Nanobot_KZ_2147762076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanobot.KZ"
        threat_id = "2147762076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5d 91 61 02 ?? 17 ?? 02 8e ?? 5d 91 ?? 20 00 01 00 00 ?? 20 00 01 00 00 5d ?? 9c}  //weight: 2, accuracy: Low
        $x_2_2 = "AlienAlbertVisitsTheUSA" ascii //weight: 2
        $x_1_3 = "AttackCompleted" ascii //weight: 1
        $x_1_4 = "AttackCompletedEvent" ascii //weight: 1
        $x_1_5 = "AIAttack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanobot_RM_2147782057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanobot.RM!MTB"
        threat_id = "2147782057"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanobot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DebuggingModes" ascii //weight: 1
        $x_1_2 = "DebuggableAttribute" ascii //weight: 1
        $x_1_3 = "SecurityProtocolType" ascii //weight: 1
        $x_10_4 = "C:\\Users\\Administrator\\Desktop\\GUIMinesweeper\\obj\\Debug\\GUIMinesweeper.pdb" ascii //weight: 10
        $x_10_5 = "http://pastex.pro/b/NebAQrCzg" ascii //weight: 10
        $x_1_6 = "You lose" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanobot_TRSI_2147812172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanobot.TRSI!MTB"
        threat_id = "2147812172"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanobot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 04 11 04 16 09 16 1f 10 28 ?? ?? ?? 0a 11 04 16 09 1f 0f 1f 10 28 ?? ?? ?? 0a 06 09 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0c 08 02 16 02 8e b7 6f ?? ?? ?? 0a 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanobot_AMAA_2147893230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanobot.AMAA!MTB"
        threat_id = "2147893230"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanobot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 07 8e 69 5d 13 08 11 04 08 6f ?? 00 00 0a 5d 13 09 07 11 08 91 13 0a 08 11 09 6f ?? 00 00 0a 13 0b 02 07 11 04 28 ?? 00 00 06 13 0c 02 17 11 0a 11 0b 11 0c 28 ?? 00 00 06 13 0d 07 11 08 02 11 0d 28 ?? 00 00 06 9c 00 11 04 17 59 13 04 11 04 16 fe 04 16 fe 01 13 0e 11 0e 2d a1}  //weight: 5, accuracy: Low
        $x_5_2 = {03 20 00 01 00 00 5d d2 0a 2b 00 06 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanobot_RSY_2147899248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanobot.RSY!MTB"
        threat_id = "2147899248"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanobot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 13 00 00 06 0a 28 04 00 00 0a 06 6f 05 00 00 0a 28 06 00 00 0a 0b 02 07 28 0b 00 00 06 0c dd 06}  //weight: 1, accuracy: High
        $x_1_2 = {03 06 91 0c 03 06 03 07 91 9c 03 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 3f e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanobot_RSD_2147899249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanobot.RSD!MTB"
        threat_id = "2147899249"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanobot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 cc 00 00 06 1a 2d 22 26 28 53 00 00 0a 06 6f 54 00 00 0a 28 55 00 00 0a 1e 2d 11}  //weight: 1, accuracy: High
        $x_1_2 = {03 06 91 18 2d 15 26 03 06 03 07 91 9c 03 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e9 06 07 32 de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanobot_SPDO_2147907201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanobot.SPDO!MTB"
        threat_id = "2147907201"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanobot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {61 07 08 17 58 07 8e 69 5d 91 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanobot_SPBM_2147910915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanobot.SPBM!MTB"
        threat_id = "2147910915"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanobot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 04 12 05 28 ?? ?? ?? 0a 08 07 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a dd 0f 00 00 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanobot_SPZM_2147911374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanobot.SPZM!MTB"
        threat_id = "2147911374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanobot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {13 13 11 1d 11 09 91 13 20 11 1d 11 09 11 28 11 20 61 11 1b 19 58 61 11 31 61 d2 9c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanobot_AMAI_2147920214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanobot.AMAI!MTB"
        threat_id = "2147920214"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanobot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 04 11 05 11 04 11 05 91 20 ?? ?? ?? ?? 59 d2 9c 00 11 05 17 58 13 05 11 05 11 04 8e 69 fe 04 13 06 11 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

