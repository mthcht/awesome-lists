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

rule Trojan_Win64_CoreFlowMain_L_2147972222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.L"
        threat_id = "2147972222"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"0544c4929c2295041930f9da68e45ccdfe36b8118798b1555311d63519b751db58\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_M_2147972226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.M"
        threat_id = "2147972226"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05e4f38090e06156b94ebf76e93ab4ccb761d761b886bbabf2df41c2bc341e8b30\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_N_2147972230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.N"
        threat_id = "2147972230"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05824da344b179aeab964412ac3a51301a2e04506419b222851467a9a581271d4a\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_O_2147972234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.O"
        threat_id = "2147972234"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05e5d8d250b0a63c143e967509176061a53cf1c162d1c56c767de8ab494b4c9849\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_P_2147972303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.P"
        threat_id = "2147972303"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05117e1c4110e0edc5ca1c539784c6a03eb34206e8ef25a8b7a729b4bb0e1a4251\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_Q_2147972307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.Q"
        threat_id = "2147972307"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"053f16fc74f145561a07737e124edcf53e0a880e84a482cf4f2f000700d95f1e7d\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_R_2147972311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.R"
        threat_id = "2147972311"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"0538d726ae3cc264c1bd8e66c6c6fa366a3dfc589567944170001e6fdbea9efb3d\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_S_2147972315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.S"
        threat_id = "2147972315"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05cb94c52170c8119f7ebc2d8afc94b9746bc7c361d91c49e7d18e96e266582a07\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_T_2147972319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.T"
        threat_id = "2147972319"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"050cd3b29c9076990738737a0a4f1920e058a543a462864a60e23ec964fd308712\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_U_2147972323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.U"
        threat_id = "2147972323"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"057d49830799b1fb3f73d7c6111f67a82322efedd8a04ff08011a38ade05459a02\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_V_2147972327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.V"
        threat_id = "2147972327"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"0550f649ecc61c797b802f3b9e3ca079dfadf64d3c81d0c0da94f9640dde727853\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_W_2147972874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.W"
        threat_id = "2147972874"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05084f9b14b02f4ffa97795a60ab1fafaf5128e3259c75459aaaeaebc80c14da78\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

