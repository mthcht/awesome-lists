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

rule Trojan_Win64_CoreFlowMain_E_2147972106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.E"
        threat_id = "2147972106"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05cd5cef689eeaf97c5e153cd6e1d4e0659edc4b37c9df850de4485ec67106ea4c\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_F_2147972110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.F"
        threat_id = "2147972110"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05440a6dd16be656d852bf8d311ac8df775d4ef9c941e108bd4851d46502aa730b\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_G_2147972114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.G"
        threat_id = "2147972114"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05a04c7c548c39e903c5913973dd55b6f3d9c1a10d346ca9d49d10b9428095823e\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_H_2147972128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.H"
        threat_id = "2147972128"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05a9183ff9c7352bcbf0a84cd6526ee94c0398eedb471b41d1da861c250a037541\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_I_2147972132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.I"
        threat_id = "2147972132"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"056999a0f3681d5deddb6243e9387c9b9a310f1bacc2a4faa1b9085a867887fb22\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_J_2147972136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.J"
        threat_id = "2147972136"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"0576babd9d1287b0069eb3b3413701d39d6acecad88fad7948d16cea3ceafc8326\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_K_2147972140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.K"
        threat_id = "2147972140"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"0500c4b4f676f3550062c72f252f673073c12e450993902fe66739a519a096491e\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

