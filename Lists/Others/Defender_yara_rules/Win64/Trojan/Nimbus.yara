rule Trojan_Win64_Nimbus_GVA_2147952969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Nimbus.GVA!MTB"
        threat_id = "2147952969"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Nimbus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 08 d8 44 08 d2 41 30 d0 41 80 f0 ff 41 80 f1 ff b2 ff 80 f2 de 45 08 c8 80 ca de 41 80 f0 ff 41 20 d0 48 63 d0 44 88 04 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Nimbus_GVB_2147953148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Nimbus.GVB!MTB"
        threat_id = "2147953148"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Nimbus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "://MediAsylum.azurewebsites.net" ascii //weight: 3
        $x_3_2 = "://TheraShelter.azurewebsites.net" ascii //weight: 3
        $x_3_3 = "://ClinicHaven.azurewebsites.net" ascii //weight: 3
        $x_3_4 = "://CareByteSolutions.azurewebsites.net" ascii //weight: 3
        $x_3_5 = "://MediCoreIT.azurewebsites.net" ascii //weight: 3
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Nimbus_GVC_2147953340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Nimbus.GVC!MTB"
        threat_id = "2147953340"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Nimbus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2a 00 d7 c6 2a 00 0b de 2a 00 d7}  //weight: 1, accuracy: High
        $x_2_2 = {14 08 00 14 64 0a 00 14 34 09 00 14 32 10 f0 0e e0 0c}  //weight: 2, accuracy: High
        $x_1_3 = {00 0f 32 0b 70 b4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

