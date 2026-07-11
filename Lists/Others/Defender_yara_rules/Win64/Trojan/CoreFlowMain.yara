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

rule Trojan_Win64_CoreFlowMain_X_2147973394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.X"
        threat_id = "2147973394"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"050459b5533149a66664a04c6a17a893c2718dbebc07d150b59d2289b14b883a3e\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_Y_2147973398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.Y"
        threat_id = "2147973398"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"054949c3391c0f75233be4fa3b803cf3252e2fe405eb6a95533235ac8fb1d45957\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_Z_2147973402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.Z"
        threat_id = "2147973402"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05668ce7c10e0cb2718c295c8a105b93b1efada65dca52cd223eef2ed99046b427\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AA_2147973406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AA"
        threat_id = "2147973406"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"0569cd842cbe55d9788a5346b2f907045d497ac14a0ce23a9d4ba9c8700c6d220e\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AB_2147973410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AB"
        threat_id = "2147973410"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"056ff01f2a898d7812ba31fa3a35e5f0e333a98559e2e0b306a740abc172e4ab52\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AC_2147973414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AC"
        threat_id = "2147973414"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05725d3d786b31ac5a0d944840b9364c4397f67fc69bf8214908c7a95ca9c47f33\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AD_2147973418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AD"
        threat_id = "2147973418"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"0578de56e37d0559e8f12ae65dc33895fe5f275965a5f6e85940f4dbae37093b12\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AE_2147973422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AE"
        threat_id = "2147973422"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"057ea00bd533ee97c92ae9d95203480074d67a80058d4a097c25987d56639a500d\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AF_2147973426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AF"
        threat_id = "2147973426"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05809b2da1d5b1a302f48b5767fd1843d54f3c516f9ab0eb26b544ffa73340292e\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AG_2147973430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AG"
        threat_id = "2147973430"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"059c2600dc49f8773a77c7111c38df8b706a2b061916819eb9e5a91d52e7129b5e\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AH_2147973434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AH"
        threat_id = "2147973434"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05a01022054c952073041dde53f8667683321183a8b378130e17b2ab12500e8714\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AI_2147973438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AI"
        threat_id = "2147973438"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05d4b570f773b687975142172d065f6ddf72537a413994d77b8da514b451826b58\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AJ_2147973442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AJ"
        threat_id = "2147973442"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05d8796fdd07ce8dfd719eeba6ac553edbd3adbdaa7af2339a5424c60bd544b64b\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AK_2147973446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AK"
        threat_id = "2147973446"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05fef7561063a8bfbd3e81623cc92fbd19aaa222a068ab2a5d77a897ba94b28971\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AL_2147973450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AL"
        threat_id = "2147973450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"0515973947c6040499dccc5eb21cac9e335f41f1402f66dec42d61823530421226\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AM_2147973454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AM"
        threat_id = "2147973454"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"056885d45a7137be429cbdb59b55c313c4a6776f9c0c23fdb19131bc2baef01436\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AN_2147973458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AN"
        threat_id = "2147973458"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"0576f87ce7ad049d7f1e24cab3780853b589bcfa9601302eb005c041f3a504fe7a\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AO_2147973462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AO"
        threat_id = "2147973462"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"058b5387927bb97bde8ce5acbe5aaf82b334375d466645c485cb34a5aa713c213e\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AP_2147973466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AP"
        threat_id = "2147973466"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"058e9edfe798d3105df7d04a04ab6a94bdc3afcda47c624eecf6dcae5b35e89c37\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AQ_2147973470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AQ"
        threat_id = "2147973470"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"059f81f46a31dcc89d2da565a31b541c77e624bd9ef00e29c85e2613af83aaf734\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AR_2147973474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AR"
        threat_id = "2147973474"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05abfaffce7c1bf1d7cfcd6a160dbbbe7fd7c24b935e68282c43a30b28cea7d52f\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AS_2147973478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AS"
        threat_id = "2147973478"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05b8d7bdf4c2b1a832b2256eb562f51ad69f2f9d8d274c6dc269cb9be5449fa84c\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowMain_AT_2147973482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowMain.AT"
        threat_id = "2147973482"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowMain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_primaryDevicePubKey{\"id\":\"primaryDevicePubKey\",\"value\":\"05e4263403161708dbe4c152d73c83ffd113fe509896008e590f730e29e849a53f\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

