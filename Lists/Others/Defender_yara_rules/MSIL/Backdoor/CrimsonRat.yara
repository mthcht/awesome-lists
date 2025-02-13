rule Backdoor_MSIL_CrimsonRat_A_2147767712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/CrimsonRat.A!MTB"
        threat_id = "2147767712"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|" ascii //weight: 10
        $x_10_2 = "<FILE_AUTO<|" ascii //weight: 10
        $x_1_3 = "set_ClientSize" ascii //weight: 1
        $x_1_4 = "cscreen" ascii //weight: 1
        $x_1_5 = "clping" ascii //weight: 1
        $x_1_6 = "capScreen" ascii //weight: 1
        $x_1_7 = "info=user|" ascii //weight: 1
        $x_1_8 = "clients_data|" ascii //weight: 1
        $x_1_9 = {5c 6f 62 6a 5c 44 65 62 75 67 [0-20] 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_CrimsonRat_B_2147777407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/CrimsonRat.B!MTB"
        threat_id = "2147777407"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|" ascii //weight: 10
        $x_10_2 = {4c 00 45 00 5f 00 41 00 55 00 [0-2] 54 00 4f 00 3c 00 7c 00 1e 00 3c 00 46 00 49 00}  //weight: 10, accuracy: Low
        $x_10_3 = {4c 45 5f 41 55 [0-2] 54 4f 3c 7c 1e 00 3c 46 49}  //weight: 10, accuracy: Low
        $x_1_4 = "set_ClientSize" ascii //weight: 1
        $x_1_5 = "cscreen" ascii //weight: 1
        $x_1_6 = {5c 6f 62 6a 5c 44 65 62 75 67 [0-20] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_7 = ".exe|" ascii //weight: 1
        $x_1_8 = {53 00 63 00 72 00 65 00 65 00 6e 00 18 00 63 00 61 00 70 00}  //weight: 1, accuracy: Low
        $x_1_9 = {53 63 72 65 65 6e 18 00 63 61 70}  //weight: 1, accuracy: Low
        $x_1_10 = {66 00 6f 00 3d 00 75 00 7a 00 [0-2] 65 00 72 00 7c 00 1e 00 69 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_11 = {66 6f 3d 75 7a [0-2] 65 72 7c 1e 00 69 6e}  //weight: 1, accuracy: Low
        $x_1_12 = "clping" ascii //weight: 1
        $x_1_13 = "getavs" ascii //weight: 1
        $x_1_14 = "-rupth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_CrimsonRat_C_2147778881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/CrimsonRat.C!MTB"
        threat_id = "2147778881"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|" ascii //weight: 10
        $x_10_2 = {4c 00 45 00 5f 00 41 00 55 00 [0-2] 54 00 4f 00 3c 00 21 00 1e 00 3c 00 46 00 49 00}  //weight: 10, accuracy: Low
        $x_10_3 = {4c 45 5f 41 55 [0-2] 54 4f 3c 21 1e 00 3c 46 49}  //weight: 10, accuracy: Low
        $x_1_4 = "set_ClientSize" ascii //weight: 1
        $x_1_5 = "cscreen" ascii //weight: 1
        $x_1_6 = ".exe|" ascii //weight: 1
        $x_1_7 = {53 00 63 00 72 00 65 00 65 00 6e 00 18 00 63 00 61 00 70 00}  //weight: 1, accuracy: Low
        $x_1_8 = {53 63 72 65 65 6e 18 00 63 61 70}  //weight: 1, accuracy: Low
        $x_1_9 = {66 00 6f 00 3d 00 75 00 7a 00 [0-2] 65 00 72 00 7c 00 1e 00 69 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_10 = {66 6f 3d 75 7a [0-2] 65 72 7c 1e 00 69 6e}  //weight: 1, accuracy: Low
        $x_1_11 = "clping" ascii //weight: 1
        $x_1_12 = "keerun" ascii //weight: 1
        $x_1_13 = "usbrun" ascii //weight: 1
        $x_1_14 = "clrklg" ascii //weight: 1
        $x_1_15 = "getavs" ascii //weight: 1
        $x_1_16 = "rupth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_CrimsonRat_D_2147780243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/CrimsonRat.D!MTB"
        threat_id = "2147780243"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|" ascii //weight: 20
        $x_5_2 = {4c 00 45 00 5f 00 41 00 55 00 [0-2] 54 00 4f 00 3c 00 21 00 1e 00 3c 00 46 00 49 00}  //weight: 5, accuracy: Low
        $x_5_3 = {4c 45 5f 41 55 [0-2] 54 4f 3c 21 1e 00 3c 46 49}  //weight: 5, accuracy: Low
        $x_5_4 = {4c 00 45 00 5f 00 41 00 55 00 [0-2] 54 00 4f 00 3c 00 7c 00 1e 00 3c 00 46 00 49 00}  //weight: 5, accuracy: Low
        $x_5_5 = {4c 45 5f 41 55 [0-2] 54 4f 3c 7c 1e 00 3c 46 49}  //weight: 5, accuracy: Low
        $x_1_6 = "set_ClientSize" ascii //weight: 1
        $x_1_7 = {53 00 63 00 72 00 65 00 65 00 6e 00 18 00 63 00 61 00 70 00}  //weight: 1, accuracy: Low
        $x_1_8 = {53 63 72 65 65 6e 18 00 63 61 70}  //weight: 1, accuracy: Low
        $x_1_9 = ".pdb" ascii //weight: 1
        $x_1_10 = {66 00 6f 00 3d 00 75 00 73 00 [0-2] 65 00 72 00 7c 00 1e 00 69 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_11 = {66 6f 3d 75 73 [0-2] 65 72 7c 1e 00 69 6e}  //weight: 1, accuracy: Low
        $x_1_12 = {66 00 6f 00 3d 00 75 00 7a 00 [0-2] 65 00 72 00 7c 00 1e 00 69 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_13 = {66 6f 3d 75 7a [0-2] 65 72 7c 1e 00 69 6e}  //weight: 1, accuracy: Low
        $x_1_14 = {74 00 61 00 76 00 73 00 0f 00 67 00 65 00}  //weight: 1, accuracy: Low
        $x_1_15 = {74 61 76 73 0f 00 67 65}  //weight: 1, accuracy: Low
        $x_1_16 = {63 00 72 00 65 00 65 00 6e 00 12 00 63 00 73 00}  //weight: 1, accuracy: Low
        $x_1_17 = {63 72 65 65 6e 12 00 63 73}  //weight: 1, accuracy: Low
        $x_1_18 = {70 00 69 00 6e 00 67 00 0f 00 63 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_19 = {70 69 6e 67 0f 00 63 6c}  //weight: 1, accuracy: Low
        $x_1_20 = "lancard" ascii //weight: 1
        $x_1_21 = "program files (x86)|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 16 of ($x_1_*))) or
            ((4 of ($x_5_*) and 11 of ($x_1_*))) or
            ((1 of ($x_20_*) and 11 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_CrimsonRat_E_2147782224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/CrimsonRat.E!MTB"
        threat_id = "2147782224"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4c 00 45 00 5f 00 41 00 55 00 [0-2] 54 00 4f 00 3c 00 21 00 1e 00 3c 00 46 00 49 00}  //weight: 10, accuracy: Low
        $x_10_2 = {4c 45 5f 41 55 [0-2] 54 4f 3c 21 1e 00 3c 46 49}  //weight: 10, accuracy: Low
        $x_5_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 5
        $x_1_4 = "$keerun" ascii //weight: 1
        $x_1_5 = "$usbwrm" ascii //weight: 1
        $x_1_6 = ".pdb" ascii //weight: 1
        $x_1_7 = "$getavs" ascii //weight: 1
        $x_1_8 = "$clrklg" ascii //weight: 1
        $x_1_9 = "$clping" ascii //weight: 1
        $x_1_10 = "$usbrun" ascii //weight: 1
        $x_1_11 = "$passl" ascii //weight: 1
        $x_1_12 = {72 00 65 00 63 00 6f 00 76 00 65 00 [0-15] 7c 00}  //weight: 1, accuracy: Low
        $x_1_13 = {72 65 63 6f 76 65 [0-15] 7c}  //weight: 1, accuracy: Low
        $x_1_14 = "$clrcmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

