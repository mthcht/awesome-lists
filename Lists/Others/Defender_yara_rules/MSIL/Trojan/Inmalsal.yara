rule Trojan_MSIL_Inmalsal_A_2147708625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Inmalsal.A"
        threat_id = "2147708625"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Inmalsal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 65 62 43 6c 69 65 6e 74 00 53 79 73 74 65 6d 2e 4e 65 74}  //weight: 1, accuracy: High
        $x_1_2 = {73 76 63 68 6f 73 74 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e}  //weight: 1, accuracy: High
        $x_1_3 = "svchost.pdb" ascii //weight: 1
        $x_1_4 = "{11111-22222-50001-00000}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Inmalsal_A_2147708625_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Inmalsal.A"
        threat_id = "2147708625"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Inmalsal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 65 62 43 6c 69 65 6e 74 00 53 79 73 74 65 6d 2e 4e 65 74}  //weight: 1, accuracy: High
        $x_1_2 = {75 73 62 73 76 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e}  //weight: 1, accuracy: High
        $x_1_3 = "usbsv.startupsv.resources" ascii //weight: 1
        $x_1_4 = "{11111-22222-50001-00000}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Inmalsal_A_2147708625_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Inmalsal.A"
        threat_id = "2147708625"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Inmalsal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 65 62 43 6c 69 65 6e 74 00 53 79 73 74 65 6d 2e 4e 65 74}  //weight: 1, accuracy: High
        $x_1_2 = "svchost.ProjectInstaller.resources" ascii //weight: 1
        $x_1_3 = "svchost.svchost.resources" ascii //weight: 1
        $x_1_4 = "{11111-22222-50001-00000}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Inmalsal_B_2147708626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Inmalsal.B"
        threat_id = "2147708626"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Inmalsal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 65 62 43 6c 69 65 6e 74 00 53 79 73 74 65 6d 2e 4e 65 74}  //weight: 1, accuracy: High
        $x_1_2 = {73 76 63 68 6f 73 74 2e 65 78 65 00 6d 73 63 6f 72 6c 69 62}  //weight: 1, accuracy: High
        $x_1_3 = {73 76 63 68 6f 73 74 2e ?? 2e 72 65 73 6f 75 72 63 65 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

