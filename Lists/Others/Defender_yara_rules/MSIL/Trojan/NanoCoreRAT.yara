rule Trojan_MSIL_NanoCoreRAT_B_2147839988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCoreRAT.B!MTB"
        threat_id = "2147839988"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCoreRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 06 5d 13 09 02 11 08 8f ?? 00 00 01 25 47 07 11 09 91 61 d2 52}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCoreRAT_C_2147841904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCoreRAT.C!MTB"
        threat_id = "2147841904"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCoreRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 01 25 16 1f 2d 9d 6f}  //weight: 2, accuracy: High
        $x_2_3 = {07 9a 1f 10 28 ?? ?? 00 0a d2 9c 07 17 58 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCoreRAT_F_2147850696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCoreRAT.F!MTB"
        threat_id = "2147850696"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCoreRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -WindowStyle Hidden Start-Sleep 5;Start-Process" wide //weight: 2
        $x_2_2 = {57 ff b6 ff 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 a1 00 00 00 5e 04 00 00 4e 01 00 00 de 13}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCoreRAT_A_2147888601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCoreRAT.A!MTB"
        threat_id = "2147888601"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCoreRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 00 00 fe 0c 01 00 fe 0c 00 00 fe 0c 01 00 93 20 a0 70 d0 fe 66 20 21 45 a1 f2 59 20 79 a6 33 e0 61 65 20 a4 ec bd ee 58 61 fe 09 00 00 61 d1 9d fe 0c 01 00 20 fd ff ff ff 66 65 66 59 25 fe 0e 01 00 20 6e 9e e3 19 66 20 89 be 04 0d 58 20 1a 20 21 f3 61 3c a5 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NanoCoreRAT_G_2147907703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NanoCoreRAT.G!MTB"
        threat_id = "2147907703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCoreRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1b 11 09 11 07 11 0a 25 17 58 13 0a 91 08 61 d2 9c 1f 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

