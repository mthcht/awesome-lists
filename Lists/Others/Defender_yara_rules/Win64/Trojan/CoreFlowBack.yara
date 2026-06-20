rule Trojan_Win64_CoreFlowBack_A_2147971301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.A"
        threat_id = "2147971301"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05bbd8d451268a1543ed3209531176954ff235d1b23c98139b24c1220c997dca52" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_B_2147972005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.B"
        threat_id = "2147972005"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "054f55ec93aca9bac362b9d91eff36a7ce451e7caba47c0b2e004ba429f9529c79" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_C_2147972009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.C"
        threat_id = "2147972009"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05cff7ecdc7cb504184c2df0f7012fa45c0c8b5a1acf8a91b4caf4704be28b167f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_D_2147972013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.D"
        threat_id = "2147972013"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "0521618aa1bc5eaab3d939ae932c4ca8493cd97690ec021eb9aa1a6ac0ed470a4f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

