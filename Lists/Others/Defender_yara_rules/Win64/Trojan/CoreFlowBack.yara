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

rule Trojan_Win64_CoreFlowBack_E_2147972108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.E"
        threat_id = "2147972108"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05cd5cef689eeaf97c5e153cd6e1d4e0659edc4b37c9df850de4485ec67106ea4c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_F_2147972112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.F"
        threat_id = "2147972112"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05440a6dd16be656d852bf8d311ac8df775d4ef9c941e108bd4851d46502aa730b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_G_2147972116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.G"
        threat_id = "2147972116"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05a04c7c548c39e903c5913973dd55b6f3d9c1a10d346ca9d49d10b9428095823e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_H_2147972130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.H"
        threat_id = "2147972130"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05a9183ff9c7352bcbf0a84cd6526ee94c0398eedb471b41d1da861c250a037541" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_I_2147972134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.I"
        threat_id = "2147972134"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "056999a0f3681d5deddb6243e9387c9b9a310f1bacc2a4faa1b9085a867887fb22" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_J_2147972138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.J"
        threat_id = "2147972138"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "0576babd9d1287b0069eb3b3413701d39d6acecad88fad7948d16cea3ceafc8326" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_K_2147972142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.K"
        threat_id = "2147972142"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "0500c4b4f676f3550062c72f252f673073c12e450993902fe66739a519a096491e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_L_2147972224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.L"
        threat_id = "2147972224"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "0544c4929c2295041930f9da68e45ccdfe36b8118798b1555311d63519b751db58" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_M_2147972228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.M"
        threat_id = "2147972228"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05e4f38090e06156b94ebf76e93ab4ccb761d761b886bbabf2df41c2bc341e8b30" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_N_2147972232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.N"
        threat_id = "2147972232"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05824da344b179aeab964412ac3a51301a2e04506419b222851467a9a581271d4a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_O_2147972236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.O"
        threat_id = "2147972236"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05e5d8d250b0a63c143e967509176061a53cf1c162d1c56c767de8ab494b4c9849" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_P_2147972305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.P"
        threat_id = "2147972305"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05117e1c4110e0edc5ca1c539784c6a03eb34206e8ef25a8b7a729b4bb0e1a4251" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_Q_2147972309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.Q"
        threat_id = "2147972309"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "053f16fc74f145561a07737e124edcf53e0a880e84a482cf4f2f000700d95f1e7d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_R_2147972313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.R"
        threat_id = "2147972313"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "0538d726ae3cc264c1bd8e66c6c6fa366a3dfc589567944170001e6fdbea9efb3d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_S_2147972317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.S"
        threat_id = "2147972317"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05cb94c52170c8119f7ebc2d8afc94b9746bc7c361d91c49e7d18e96e266582a07" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_T_2147972321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.T"
        threat_id = "2147972321"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "050cd3b29c9076990738737a0a4f1920e058a543a462864a60e23ec964fd308712" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_U_2147972325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.U"
        threat_id = "2147972325"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "057d49830799b1fb3f73d7c6111f67a82322efedd8a04ff08011a38ade05459a02" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_V_2147972329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.V"
        threat_id = "2147972329"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "0550f649ecc61c797b802f3b9e3ca079dfadf64d3c81d0c0da94f9640dde727853" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_W_2147972876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.W"
        threat_id = "2147972876"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05084f9b14b02f4ffa97795a60ab1fafaf5128e3259c75459aaaeaebc80c14da78" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_X_2147973321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.X"
        threat_id = "2147973321"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "050459b5533149a66664a04c6a17a893c2718dbebc07d150b59d2289b14b883a3e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_Y_2147973325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.Y"
        threat_id = "2147973325"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "054949c3391c0f75233be4fa3b803cf3252e2fe405eb6a95533235ac8fb1d45957" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_Z_2147973329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.Z"
        threat_id = "2147973329"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05668ce7c10e0cb2718c295c8a105b93b1efada65dca52cd223eef2ed99046b427" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_AA_2147973333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.AA"
        threat_id = "2147973333"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "0569cd842cbe55d9788a5346b2f907045d497ac14a0ce23a9d4ba9c8700c6d220e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_AB_2147973337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.AB"
        threat_id = "2147973337"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "056ff01f2a898d7812ba31fa3a35e5f0e333a98559e2e0b306a740abc172e4ab52" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_AC_2147973341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.AC"
        threat_id = "2147973341"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05725d3d786b31ac5a0d944840b9364c4397f67fc69bf8214908c7a95ca9c47f33" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_AD_2147973345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.AD"
        threat_id = "2147973345"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "0578de56e37d0559e8f12ae65dc33895fe5f275965a5f6e85940f4dbae37093b12" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_AE_2147973349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.AE"
        threat_id = "2147973349"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "057ea00bd533ee97c92ae9d95203480074d67a80058d4a097c25987d56639a500d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_AF_2147973353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.AF"
        threat_id = "2147973353"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05809b2da1d5b1a302f48b5767fd1843d54f3c516f9ab0eb26b544ffa73340292e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_AG_2147973357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.AG"
        threat_id = "2147973357"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "059c2600dc49f8773a77c7111c38df8b706a2b061916819eb9e5a91d52e7129b5e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_AH_2147973361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.AH"
        threat_id = "2147973361"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05a01022054c952073041dde53f8667683321183a8b378130e17b2ab12500e8714" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_AI_2147973365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.AI"
        threat_id = "2147973365"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05d4b570f773b687975142172d065f6ddf72537a413994d77b8da514b451826b58" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_AJ_2147973369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.AJ"
        threat_id = "2147973369"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05d8796fdd07ce8dfd719eeba6ac553edbd3adbdaa7af2339a5424c60bd544b64b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoreFlowBack_AK_2147973373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoreFlowBack.AK"
        threat_id = "2147973373"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoreFlowBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 53 77 61 72 6d 4e 6f 64 65 73 46 6f 72 50 75 62 6b 65 79 22 42 [0-66] 41}  //weight: 1, accuracy: Low
        $x_1_2 = "05fef7561063a8bfbd3e81623cc92fbd19aaa222a068ab2a5d77a897ba94b28971" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

