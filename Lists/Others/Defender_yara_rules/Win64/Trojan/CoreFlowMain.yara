rule Trojan_Win64_CoreFlowMain_A_2147970894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.A"
        threat_id = "2147970894"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05bbd8d451268a1543ed3209531176954ff235d1b23c98139b24c1220c997dca52\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_B_2147972003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.B"
        threat_id = "2147972003"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"054f55ec93aca9bac362b9d91eff36a7ce451e7caba47c0b2e004ba429f9529c79\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_C_2147972007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.C"
        threat_id = "2147972007"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05cff7ecdc7cb504184c2df0f7012fa45c0c8b5a1acf8a91b4caf4704be28b167f\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_D_2147972011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.D"
        threat_id = "2147972011"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"0521618aa1bc5eaab3d939ae932c4ca8493cd97690ec021eb9aa1a6ac0ed470a4f\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

