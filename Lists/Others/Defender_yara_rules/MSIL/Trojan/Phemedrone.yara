rule Trojan_MSIL_Phemedrone_AO_2147904028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Phemedrone.AO!MTB"
        threat_id = "2147904028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Phemedrone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fe 0e 04 00 fe 0c 03 00 fe 0c 04 00 61 d1 fe 0e 05 00 fe 0c 01 00 fe 0c 05 00 6f}  //weight: 2, accuracy: High
        $x_2_2 = {fe 0c 00 00 fe 0c 02 00 91 fe 0e 03 00 7e ?? 00 00 04 fe 0c 02 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Phemedrone_APH_2147914788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Phemedrone.APH!MTB"
        threat_id = "2147914788"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Phemedrone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 16 0b 2b 1c 00 06 07 03 07 91 04 07 04 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 00 07 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "Debug\\Phemedrone-Stealer.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Phemedrone_APH_2147914788_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Phemedrone.APH!MTB"
        threat_id = "2147914788"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Phemedrone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 0b 2b 23 11 0a 11 0b 91 13 0c 00 11 09 12 0c 72 00 0e 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 26 00 11 0b 17 58 13 0b 11 0b 11 0a 8e 69}  //weight: 2, accuracy: Low
        $x_1_2 = "murderousattack.xyz" wide //weight: 1
        $x_1_3 = "Phemedrone-Stealer.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Phemedrone_APD_2147921663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Phemedrone.APD!MTB"
        threat_id = "2147921663"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Phemedrone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fe 0c 02 00 7e 44 01 00 04 6f ?? 00 00 0a 5d 6f ?? 01 00 0a fe 0e 03 00 fe 0c 03 00 61 d1 fe 0e 04 00 fe 0c 01 00 fe 0c 04 00 6f ?? 01 00 0a 26 fe 0c 02 00 20 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 0c 00 00 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Phemedrone_APM_2147930867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Phemedrone.APM!MTB"
        threat_id = "2147930867"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Phemedrone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 13 07 11 08 08 11 07 91 58 20 00 01 00 00 5d 13 08 08 11 07 91 0d 08 11 07 08 11 08 91 9c 08 11 08 09 9c 08 08 11 07 91 08 11 08 91 58 20 00 01 00 00 5d 91 13 0a 07 11 09 02 11 09 91 11 0a 61 d2 9c 11 09 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

