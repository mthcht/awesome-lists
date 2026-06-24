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

