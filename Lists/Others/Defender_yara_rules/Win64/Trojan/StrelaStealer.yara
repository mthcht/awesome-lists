rule Trojan_Win64_StrelaStealer_PQA_2147850678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.PQA!MTB"
        threat_id = "2147850678"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 cf 83 f7 ?? 81 e7 ?? ?? ?? ?? 41 89 df 41 81 f7 ?? ?? ?? ?? 45 21 f9 44 09 cf 41 83 f3 ?? 83 f7 ?? 41 89 d9 41 81 f1 ?? ?? ?? ?? 41 09 fb 41 81 c9 ?? ?? ?? ?? 41 83 f3 ?? 45 21 cb 45 89 f1 45 21 d9 45 31 de 45 09 f1}  //weight: 1, accuracy: Low
        $x_1_2 = {45 31 d4 41 09 f0 41 83 f0 ?? 81 cb ?? ?? ?? ?? 41 21 d8 45 09 c4 45 89 e8 41 83 f0 ?? 41 81 e0 ?? ?? ?? ?? 41 89 fa 41 81 f2 ?? ?? ?? ?? 45 21 d5 44 89 e6 83 f6 ff 81 e6 ?? ?? ?? ?? 45 21 d4 45 09 e8 44 09 e6 41 31 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_StrelaStealer_MA_2147851420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.MA!MTB"
        threat_id = "2147851420"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 89 c8 41 81 e8 ?? ?? ?? ?? 41 81 c0 ?? ?? ?? ?? 41 81 c0 ?? ?? ?? ?? 41 89 c1 45 29 c1 41 89 c0 41 81 e8 ?? ?? ?? ?? 45 01 c1 41 89 c0 45 29 c8 41 81 e8 ?? ?? ?? ?? 41 81 e8 ?? ?? ?? ?? 41 81 c0 ?? ?? ?? ?? 41 81 e8 ?? ?? ?? ?? 41 81 e8 ?? ?? ?? ?? 41 81 c0 ?? ?? ?? ?? 83 e8 01 41 01 c0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_DA_2147851904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.DA!MTB"
        threat_id = "2147851904"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c8 e8 ?? ?? ?? ?? 48 29 c4 48 89 e0 48 8b 8d ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 89 c8 e8 ?? ?? ?? ?? 48 29 c4 48 89 e0 48 8b 8d ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 89 c8 e8 ?? ?? ?? ?? 48 29 c4 48 89 e0 48 8b 8d ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 89 c8 e8 ?? ?? ?? ?? 48 29 c4 48 89 e0 48 8b 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c1 48 81 c1 01 00 00 00 48 89 8d ?? ?? ?? ?? 8a 10 48 8b 85 ?? ?? ?? ?? 48 89 c1 48 81 c1 01 00 00 00 48 89 8d ?? ?? ?? ?? 88 10 e9 07 00 48 8b 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_RF_2147852438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.RF!MTB"
        threat_id = "2147852438"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6f 75 74 2e 64 6c 6c 00 68 65 6c 6c 6f}  //weight: 5, accuracy: High
        $x_1_2 = "yzxmJxiCepzAGtyDwesjMeoxTYeovOcVymrnHdu" ascii //weight: 1
        $x_1_3 = "CwPEYQDtiojhbfPDTeLevmduTtbJJZIBnnckJZwSbZqeAA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_StrelaStealer_DAW_2147852477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.DAW!MTB"
        threat_id = "2147852477"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 f1 ff 41 80 ca 01 44 20 d1 41 08 cb 80 f2 ff 41 80 f3 ff 40 80 f6 00 44 08 da 40 80 ce 00 80 f2 ff 40 20 f2 88 c1 20 d1 30 d0 08 c1 f6 c1 01 0f}  //weight: 2, accuracy: High
        $x_2_2 = {41 88 c9 41 30 d1 41 20 c9 88 c1 80 f1 ff 44 88 ca 80 f2 ff 80 f3 01 41 88 ca 41 80 e2 ff 20 d8 41 88 d3 41 80 e3 ff 41 20 d9 41 08 c2 45 08 cb 45 30 da 08 d1 80 f1 ff 80 cb 01 20 d9 41 08 ca 41 f6 c2 01 0f}  //weight: 2, accuracy: High
        $x_1_3 = {08 cb 30 d8 40 88 f9 80 e1 01 40 80 f7 01 40 08 f9 80 f1 ff 41 88 c1 41 30 c9 41 20 c1 88 d0 44 20 c8 44 30 ca 08 d0 a8 01 0f 85}  //weight: 1, accuracy: High
        $x_1_4 = {40 80 f7 01 41 20 f9 45 88 d6 41 80 f6 ff 41 80 e6 ff 41 20 fa 45 08 cb 45 08 d6 45 30 f3 41 88 d9 41 80 f1 ff 45 88 da 41 80 f2 ff 40 80 f6 00 44 88 cf 40 80 e7 00 40 20 f3 45 88 d6 41 80 e6 00 41 20 f3 40 08 df 45 08 de 44 30 f7 45 08 d1 41 80 f1 ff 40 80 ce 00 41 20 f1 44 08 cf 40 f6 c7 01 0f 85}  //weight: 1, accuracy: High
        $x_1_5 = {6f 75 74 2e 64 6c 6c 00 65 6e 74 72 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_StrelaStealer_DW_2147890338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.DW!MTB"
        threat_id = "2147890338"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "edom SOD ni nur eb tonnac margorp sihT" ascii //weight: 1
        $x_1_2 = "F4rw1rd j5mp w3th n4 l1b2l d2f3n2d" ascii //weight: 1
        $x_1_3 = "ch21t 2ng3n2" ascii //weight: 1
        $x_1_4 = "New!!! ch21t-e-coins! Now you can buy ch21t-e-coins to be able to use ch21t" ascii //weight: 1
        $x_1_5 = "ch21t2ng3n246_68x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GPAA_2147895078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GPAA!MTB"
        threat_id = "2147895078"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 75 74 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 4d 65 6d 43 70 79 00 53 74 72 43 6d 70}  //weight: 2, accuracy: High
        $x_2_2 = {78 00 78 2e 31 00 78 2e 31 31 00 78 2e 33 00 78 2e 35 00 78 2e 37 00 78 2e 39 00 79 00 79 2e 31 30 00 79 2e 31 32 00 79 2e 32 00 79 2e 34 00 79 2e 36 00 79 2e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GPAB_2147896936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GPAB!MTB"
        threat_id = "2147896936"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 75 74 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 4d 65 6d 43 70 79 00 53 74 72 43 6d 70}  //weight: 2, accuracy: High
        $x_2_2 = {67 42 75 66 00 78 00 78 2e 31 00 78 2e 31 31 00 78 2e 31 33 00 78 2e 33 00 78 2e 35 00 78 2e 37 00 78 2e 39 00 79 00 79 2e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_DAS_2147900748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.DAS!MTB"
        threat_id = "2147900748"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 80 f2 ff 40 80 f6 00 44 88 cf 40 80 e7 00 40 20 f3 45 88 d6 41 80 e6 00 41 20 f3 40 08 df 45 08 de 44 30 f7 45 08 d1 41 80 f1 ff 40 80 ce 00 41 20 f1 44 08 cf 40 f6 c7 01 0f 85}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GPAC_2147900833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GPAC!MTB"
        threat_id = "2147900833"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 e1 01 83 f9 00 41 0f 94 c2 83 fa 0a 41 0f 9c c3 44 88 d3 80 f3 ff 80 e3 01 40 b6 01 40 88 f7 40 80 f7 01 45 88 d6 41 20}  //weight: 2, accuracy: High
        $x_2_2 = {00 6f 75 74 2e 64 6c 6c 00 78 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_DAT_2147901370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.DAT!MTB"
        threat_id = "2147901370"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 88 de 40 80 f6 ff 40 80 e6 01 40 b7 01 41 88 fe 41 80 f6 01 45 88 df 45 20 f7 44 08 fe}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_ASDA_2147901459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ASDA!MTB"
        threat_id = "2147901459"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 80 e0 ff 45 20 f2 45 08 e7 45 08 d0 45 30 c7 44 8a}  //weight: 1, accuracy: High
        $x_1_2 = {44 08 c1 80 f1 ff 41 80 ce 01 44 20 f1 41 08 cf}  //weight: 1, accuracy: High
        $x_1_3 = {41 80 f1 01 41 08 d2 41 80 c9 01 41 80 f2 ff 45 20 ca 8a}  //weight: 1, accuracy: High
        $x_1_4 = {41 08 fc 45 08 f5 45 30 ec 45 08 d9 41 80 f1 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_StrelaStealer_ASDB_2147901460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ASDB!MTB"
        threat_id = "2147901460"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 29 c4 48 8d ac 24 80 00 00 00 31 c0 8b 0d a3 [0-2] 00 8b 15 a9 [0-2] 00 41 [0-16] 41 ?? c0 [0-4] 41 81}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_ASDC_2147901494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ASDC!MTB"
        threat_id = "2147901494"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 41 57 41 56 41 55 41 54 56 57 53 b8 ?? ?? 00 00 e8 [0-3] 00 48 29 c4 48 8d ac 24 80 00 00 00 31 c0 8b 0d a3 ?? ?? 00 8b 15 a9 ?? ?? 00 41 89 [0-8] 41}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GPAE_2147901647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GPAE!MTB"
        threat_id = "2147901647"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {41 09 d9 09 fd 41 31 e9 44 89 cf 83 f7 ff 81 f7 ff ff ff ff 83 e7 ff 44 89 d3 81 f3 ff ff ff ff 81 e3 ff ff ff ff 44 89 d5 81 f5 ff ff ff ff 81 e5 ff ff ff ff 09 eb 83 f3 ff 44 89 d5}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_ASCD_2147902019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ASCD!MTB"
        threat_id = "2147902019"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 57 41 56 41 55 41 54 56 57 55 53 48 81 ec ?? ?? ?? 00 c7 84 24 ?? ?? ?? 00 00 00 00 00 81 bc 24 ?? ?? ?? 00 cc 0c 00 00 0f ?? ?? ?? 00 00 e9 00 00 00 00 31 c0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_ASDE_2147902417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ASDE!MTB"
        threat_id = "2147902417"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 41 57 41 56 41 55 41 54 56 57 53 48 81 ec [0-3] 00 48 8d ac 24 80 00 00 00 e8 [0-3] 00 c7 85 [0-3] 00 00 00 00 00 c7 85 [0-3] 00 00 00 00 00 31 c0 8b 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GPAG_2147902473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GPAG!MTB"
        threat_id = "2147902473"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 0f 9c c2 45 88 d3 41 80 f3 ff 44 88 cb 44 30 db 44 20 cb 45 88 cb 41 80 f3 ff 44 88 d6 44 20 de 41 80 f2 ff 45 20 d1 44 08 ce 41 88 d9 41 20 f1 40 30 f3 41 08 d9 41 f6 c1 01 0f}  //weight: 5, accuracy: High
        $x_2_2 = {00 6f 75 74 2e 64 6c 6c 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GPAF_2147902606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GPAF!MTB"
        threat_id = "2147902606"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 29 c4 48 89 e0 48 8b 4d ?? 48 89 45 ?? 48 89 c8 e8 ?? ?? ?? ?? 48 29 c4 48 89 e0 48 8b 4d ?? 48 89 45 ?? 48 89 c8 e8 ?? ?? ?? ?? 48 29 c4 48 89 e0 48 8b 4d}  //weight: 5, accuracy: Low
        $x_2_2 = {00 6f 75 74 2e 64 6c 6c 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_ASDF_2147903154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ASDF!MTB"
        threat_id = "2147903154"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 57 41 56 41 55 41 54 56 57 55 53 b8 ?? ?? 00 00 e8 ?? ?? ?? 00 48 29 c4 c7 84 24 ?? ?? 00 00 00 00 00 00 81 bc 24 ?? ?? 00 00 cc 0c 00 00 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GPAJ_2147904033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GPAJ!MTB"
        threat_id = "2147904033"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 80 f2 ff 45 20 d1 44 08 ce 41 88 d9 41 80 f1 ff 41 88 f2 41 80 f2 ff 41 b3 01 41 80 f3 01 44 88 cf 40 80 e7 ff 44 20 db 45 88 d6 41 80 e6 ff 44 20 de 40 08 df 41 08 f6 44 30 f7 45 08 d1 41 80 f1 ff 41 80 cb 01 45 20 d9 44 08}  //weight: 5, accuracy: High
        $x_5_2 = {83 e0 01 83 f8 00 41 0f 94 c1 83 fa 0a 41 0f 9c c2 45 88 cb 41 80 f3 ff 41 80 e3 01 b3 01 40 88 de 40 80 f6 01 44 88 cf 40 20 f7 41 88 de 41 80 f6 01 41 80 e6 ff 40 80 e6 01 41 08 fb 41 08 f6 45 30 f3 44 88 d6 40 80 f6 ff 40 80}  //weight: 5, accuracy: High
        $x_5_3 = {80 f3 ff 80 e3 00 40 b6 01 40 88 f7 40 80 f7 00 45 88 d6 41 20 fe 41 88 f7 41 80 f7 01 41 80 e7 00 40 80 e7 01 44 08 f3 41 08 ff 44 30 fb 44 88 df 40 80 f7 ff 40 80 e7 01 41 88 f6 41 80 f6 01 45 88 df 45 20 f7 44 08 ff 41 88}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_StrelaStealer_ASDG_2147905232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ASDG!MTB"
        threat_id = "2147905232"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 57 41 56 41 55 41 54 56 57 55 53 b8 ?? ?? 00 00 e8 ?? ?? ?? 00 48 29 c4 48 8d 84 24 ?? ?? 00 00 48 89 c1 48 8d 15 ?? ?? ?? 00 41 b8 04 00 00 00 e8 ?? ?? ?? 00 48 8d 0d ?? ?? ?? 00 48 89 ca 48 81 c2}  //weight: 5, accuracy: Low
        $x_5_2 = {41 57 41 56 41 55 41 54 56 57 55 53 48 81 ec ?? ?? 00 00 48 8d 84 24 ?? ?? 00 00 48 89 c1 48 8d 15 ?? ?? ?? 00 41 b8 04 00 00 00 e8 ?? ?? ?? 00 48 8d 0d ?? ?? ?? 00 48 89 ca 48 81 c2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_StrelaStealer_GPAK_2147906411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GPAK!MTB"
        threat_id = "2147906411"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 09 f2 44 09 df 41 31 fa 45 89 d3 41 83 f3 ff 89 ce 44 31 de 21 ce 45 89 cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GPAD_2147910326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GPAD!MTB"
        threat_id = "2147910326"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 45 f8 48 83 45 f8 08 eb 22 48 8b 45 f8 48 89 45 f0 48 8b 45 f0 48 8b 00 48 85 c0 74 09 48 8b 45 f0 48 8b 00 ff d0 48 83 45 f8}  //weight: 1, accuracy: High
        $x_1_2 = {00 6f 75 74 2e 64 6c 6c 00 6d 61 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GPAX_2147910327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GPAX!MTB"
        threat_id = "2147910327"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "strela" ascii //weight: 1
        $x_1_2 = "/server.php" ascii //weight: 1
        $x_1_3 = "IMAP Server" ascii //weight: 1
        $x_1_4 = "IMAP User" ascii //weight: 1
        $x_1_5 = "IMAP Password" ascii //weight: 1
        $x_1_6 = "Thunderbird\\Profiles" ascii //weight: 1
        $x_1_7 = "%s%s\\logins.json" ascii //weight: 1
        $x_1_8 = "%s%s\\key4.db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_ZX_2147913904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ZX!MTB"
        threat_id = "2147913904"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 85 b8 06 00 00 48 8b 8d 20 01 00 00 48 8b 11 48 8b 8d b0 06 00 00 48 83 ec 20 48 89 4d 80 48 89 c1 48 8b 45 80 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_CCJA_2147914590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.CCJA!MTB"
        threat_id = "2147914590"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 41 57 41 56 41 55 41 54 56 57 53 48 81 ec ?? ?? ?? ?? 48 8d ac 24 80 00 00 00 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 89 c1 81 e9 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {03 00 01 00 00 00 01 00 00 00 01 00 00 00 28 ?? 03 00 2c ?? 03 00 30 ?? 03 00 a0 15 00 00 3a ?? 03 00 00 00 6f 75 74 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GND_2147914768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GND!MTB"
        threat_id = "2147914768"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 41 57 41 56 41 55 41 54 56 57 53 48 81 ec ?? ?? ?? ?? 48 8d ac 24 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? 00 00 89 c1 81 e9 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? e9 00 00 00 00 8b 85 ?? ?? ?? ?? 2d ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? e9 00 00 00 00 8b 85 ?? ?? 00 00 2d ?? ?? ?? ?? 0f 84}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_ASG_2147914802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ASG!MTB"
        threat_id = "2147914802"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {55 41 57 41 56 41 55 41 54 56 57 53 48 81 ec ?? ?? 00 00 48 8d ac 24 80 00 00 00 c7 45 ?? ?? ?? ?? ?? 8b 45 ?? 89 c1 81 e9 ?? ?? ?? ?? 89 45 ?? 0f 84 ?? ?? 00 00 e9 00 00 00 00 8b 45 ?? 2d ?? ?? ?? ?? 0f 84 ?? ?? 00 00 e9 00 00 00 00 8b 45 ?? 2d}  //weight: 4, accuracy: Low
        $x_4_2 = {55 41 57 41 56 41 54 56 57 53 48 81 ec ?? ?? 00 00 48 8d ac 24 80 00 00 00 c7 45 ?? ?? ?? ?? ?? 8b 45 ?? 89 c1 81 e9 ?? ?? ?? ?? 89 45 ?? 0f 84 ?? ?? 00 00 e9 00 00 00 00 8b 45 ?? 2d ?? ?? ?? ?? 0f 84 ?? ?? 00 00 e9 00 00 00 00 8b 45 ?? 2d ?? ?? ?? ?? 0f 84}  //weight: 4, accuracy: Low
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_StrelaStealer_GNF_2147915024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GNF!MTB"
        threat_id = "2147915024"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 57 41 56 56 57 53 48 81 ec ?? ?? ?? ?? 48 8d ac 24 ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 8b 45 ?? 89 c1 81 e9 ?? ?? ?? ?? 89 45 ?? 0f 84 ?? ?? ?? ?? e9 00 00 00 00 8b 45 ?? 2d ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? e9 00 00 00 00 8b 45 ?? 2d ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? e9 00 00 00 00 8b 45 ?? 2d ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? e9 00 00 00 00 8b 45 ?? 2d ?? ?? ?? ?? 0f 84}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_ASI_2147915382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ASI!MTB"
        threat_id = "2147915382"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {21 f2 44 09 ?? 09 ?? 31 ?? 43 88 0c 10}  //weight: 4, accuracy: Low
        $x_4_2 = {21 f3 44 09 ?? 09 ?? 31 ?? 43 88 0c 10}  //weight: 4, accuracy: Low
        $x_4_3 = {21 ca 83 f7 ff 41 21 ff 44 09 fa 43 88 14 10 c7 44 24 7c}  //weight: 4, accuracy: High
        $x_4_4 = {21 f1 09 cb 43 88 1c 10 c7 44 24 7c}  //weight: 4, accuracy: High
        $x_4_5 = {21 f2 44 09 f9 41 09 d3 44 31 d9 43 88 0c 10 c7 44 24 7c}  //weight: 4, accuracy: High
        $x_4_6 = {21 f1 44 09 fa 41 09 cb 44 31 da 43 88 14 10 c7 44 24 7c}  //weight: 4, accuracy: High
        $x_4_7 = {21 ce 45 09 f3 47 88 1c 10}  //weight: 4, accuracy: High
        $x_4_8 = {21 d1 31 d7 09 f9 43 88 0c 10}  //weight: 4, accuracy: High
        $x_4_9 = {21 ca 31 cf 09 fa 43 88 14 10 c7 44 24 7c}  //weight: 4, accuracy: High
        $x_4_10 = {21 f1 09 cb 43 88 1c 10 c7 84 24}  //weight: 4, accuracy: High
        $x_4_11 = {41 21 f6 09 ca 45 09 f3 44 31 da 43 88 14 10}  //weight: 4, accuracy: High
        $x_4_12 = {21 f2 09 d3 43 88 1c 10 c7 84 24}  //weight: 4, accuracy: High
        $x_4_13 = {45 21 de 44 09 f2 43 88 14 10 c7 84 24}  //weight: 4, accuracy: High
        $x_4_14 = {21 f5 44 09 d9 09 ea 31 d1 43 88 0c 10}  //weight: 4, accuracy: High
        $x_1_15 = "DllRegisterServer" ascii //weight: 1
        $x_1_16 = {41 b8 04 00 00 00 e8 ?? ?? 00 00 48 8d 0d ?? ?? 00 00 48 89 ca 48 81 c2 14 27 00 00 48 81 c1 04 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_StrelaStealer_GPAL_2147915389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GPAL!MTB"
        threat_id = "2147915389"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 89 c2 48 31 ca 48 21 c2 48 8b 85 ?? 00 00 00 48 89 10}  //weight: 4, accuracy: Low
        $x_4_2 = {49 89 d0 49 31 c8 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 31 ca 4c 09 c0 48 09 ca 48 35}  //weight: 4, accuracy: Low
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_StrelaStealer_ASR_2147915426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ASR!MTB"
        threat_id = "2147915426"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 d0 48 89 d0 48 c1 e0 02 48 01 d0 48 c1 e0 03 4c 01 c0 48 8b 40 08 48 8d 55 f8 49 89 d1 45 89 d0 48 89 ca 48 89 c1 48 8b 05 49 72 02 00 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_MBXH_2147915964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.MBXH!MTB"
        threat_id = "2147915964"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {38 30 00 00 01 00 00 00 01 00 00 00 01 00 00 00 45 30 00 00 49 30 00 00 4d 30 00 00 50 72 6f 6a 65 63 74 31 2e 64 6c 6c [0-32] 65 6e 74 72 79 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_ASJ_2147915974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ASJ!MTB"
        threat_id = "2147915974"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff 03 00 00 42 0f b6 ?? ?? 04 42 32 ?? ?? 04 04 00 00 80 ?? 0c 42 88 ?? ?? 04 04 00 00 48 83 ?? 01 84 c0 75}  //weight: 4, accuracy: Low
        $x_4_2 = {ff 03 00 00 0f b6 ?? ?? 04 32 84 1f 04 04 00 00 34 0c 88 84 1f 04 04 00 00 48 83 c7 01 4c 39 f7 72}  //weight: 4, accuracy: Low
        $x_4_3 = {ff 03 00 00 0f b6 ?? ?? 04 32 ?? ?? 04 04 00 00 ?? ?? 0c 88 ?? ?? 04 04 00 00 48 83 ?? 01 4c 39 ?? 72}  //weight: 4, accuracy: Low
        $x_1_4 = "entry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_StrelaStealer_CCJC_2147915992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.CCJC!MTB"
        threat_id = "2147915992"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff 03 00 00 0f b6 ?? ?? 04 32 ?? ?? 04 04 00 00 80 f1 0c 88 8c 2b 04 04 00 00 48 83 c3 01 84 d2 75 d5}  //weight: 4, accuracy: Low
        $x_4_2 = {ff 03 00 00 42 0f b6 ?? ?? 04 42 32 ?? ?? 04 04 00 00 80 ?? 0c 42 88 ?? ?? 04 04 00 00 48 83 c3 01 [0-3] 75}  //weight: 4, accuracy: Low
        $x_1_3 = "entry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_StrelaStealer_ASK_2147916020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ASK!MTB"
        threat_id = "2147916020"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff 03 00 00 0f b6 ?? ?? 04 32 ?? ?? 04 04 00 00 34 0c 88 84 ?? 04 04 00 00 48 83 c1 01 4c 39 ?? 72}  //weight: 4, accuracy: Low
        $x_4_2 = {ff 03 00 00 42 0f b6 ?? ?? 04 42 32 ?? ?? 04 04 00 00 80 ?? 0c 42 88 ?? ?? 04 04 00 00 48 83 ?? 01 84 db 75}  //weight: 4, accuracy: Low
        $x_4_3 = {ff 03 00 00 0f b6 ?? ?? 04 32 8c 33 04 04 00 00 80 f1 0c 88 8c 33 04 04 00 00 48 83 c3 01 84 d2 75}  //weight: 4, accuracy: Low
        $x_1_4 = "entry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_StrelaStealer_GZM_2147916022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GZM!MTB"
        threat_id = "2147916022"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c1 81 e1 ?? ?? ?? ?? 42 0f b6 4c ?? ?? 30 0c 02 48 83 c0 ?? 4c 39 c8}  //weight: 10, accuracy: Low
        $x_10_2 = {89 c2 81 e2 ?? ?? ?? ?? 42 0f b6 54 ?? ?? 30 14 01 48 83 c0 ?? 4c 39 c8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_StrelaStealer_CCJD_2147916028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.CCJD!MTB"
        threat_id = "2147916028"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff 03 00 00 0f b6 ?? ?? 04 32 ?? ?? 04 04 00 00 80 ?? 0c 88 ?? ?? 04 04 00 00 48 83 ?? 01 84 ?? 75}  //weight: 4, accuracy: Low
        $x_1_2 = "entry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_DB_2147916055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.DB!MTB"
        threat_id = "2147916055"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {ff 03 00 00 0f b6 ?? ?? 04 32 84 ?? ?? 04 00 00 34 0c 88 84 ?? ?? 04 00 00 48 83 ?? 01 4c 39 ?? 72 03 00 89 ?? 25}  //weight: 50, accuracy: Low
        $x_50_2 = {ff 03 00 00 [0-1] 0f b6 ?? ?? 04 30 14 08 48 83 c1 01 4c 39 ?? 72 04 00 89 ?? 81}  //weight: 50, accuracy: Low
        $x_1_3 = "entry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_1_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_StrelaStealer_ASL_2147916133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ASL!MTB"
        threat_id = "2147916133"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 83 ec 10 48 89 7c 24 20 31 c9 ba 1a 00 00 00 45 31 c0 45 31 c9 4c 8b 25 06 28 05 00 41 ff d4 48 83 c4 10 48 89 f9 4c 8d 3d 2b f6 04 00 4c 89 fa 4c 89 eb 41 ff d5 41 b8 04 01 00 00 48 89 f1 31 d2 e8 14 93 04 00}  //weight: 2, accuracy: High
        $x_1_2 = "c8d79d55-6723-4d85-9f23-7252e2e2bff1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_ASL_2147916133_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ASL!MTB"
        threat_id = "2147916133"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff 03 00 00 0f b6 ?? ?? 04 32 ?? ?? 04 04 00 00 80 f2 0c 88 ?? 3d 04 04 00 00 48 83 ?? 01 48 39 ?? 72}  //weight: 4, accuracy: Low
        $x_4_2 = {ff 03 00 00 0f b6 ?? ?? 04 32 ?? ?? 04 04 00 00 34 0c 88 84 ?? 04 04 00 00 48 83 c1 01 4c 39 ?? 72}  //weight: 4, accuracy: Low
        $x_4_3 = {ff 03 00 00 42 0f b6 4c ?? 04 42 32 8c ?? 04 04 00 00 80 f1 0c 42 88 8c ?? 04 04 00 00 48 83 c5 01 84 d2 75}  //weight: 4, accuracy: Low
        $x_4_4 = {0f b6 5c 03 04 41 32 9c 03 05 04 00 00 80 f3 0c 41 88 9c 03 05 04 00 00 49 83 c3 02 4d 39 dc 75}  //weight: 4, accuracy: High
        $x_1_5 = "entry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_StrelaStealer_ASM_2147916224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ASM!MTB"
        threat_id = "2147916224"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff 03 00 00 42 0f b6 ?? ?? 04 42 32 ?? ?? 04 04 00 00 34 0c 42 88 84 ?? 04 04 00 00 48 83 ?? 01 84 ?? 75}  //weight: 4, accuracy: Low
        $x_4_2 = {ff 03 00 00 42 0f b6 ?? ?? 04 42 32 ?? ?? 04 04 00 00 34 0c 42 88 84 ?? 04 04 00 00 48 83 c3 01 45 84 ?? 75}  //weight: 4, accuracy: Low
        $x_4_3 = {ff 03 00 00 [0-1] 0f b6 4c 39 04 [0-1] 32 8c 38 04 04 00 00 80 f1 0c [0-1] 88 8c 38 04 04 00 00 8d 48 01 81 e1 ff 03 00 00 [0-1] 0f b6 4c 39 04 [0-1] 32 8c 38 05 04 00 00 80 f1 0c [0-1] 88 8c 38 05 04 00 00 48 83 c0 02 49 39 [0-1] 75}  //weight: 4, accuracy: Low
        $x_4_4 = {ff 03 00 00 42 0f b6 ?? ?? 04 42 32 ?? ?? 04 04 00 00 80 ?? 0c 42 88 ?? ?? 04 04 00 00 48 83 c5 01 84 ?? 75}  //weight: 4, accuracy: Low
        $x_1_5 = "entry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_StrelaStealer_ASN_2147916715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ASN!MTB"
        threat_id = "2147916715"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {48 21 c8 48 f7 d1 48 21 cd 48 09 c5 48 31 cd}  //weight: 4, accuracy: High
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GPAN_2147916981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GPAN!MTB"
        threat_id = "2147916981"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 89 c2 20 c2 44 30 c0 08 d0 89 c2}  //weight: 1, accuracy: High
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GPX_2147924451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GPX!MTB"
        threat_id = "2147924451"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 b8 00 30 00 00 41 b9 40 00 00 00 31 c9 ff d0 48 89 44 24}  //weight: 2, accuracy: High
        $x_5_2 = {4c 01 e8 48 05 04 04 00 00 48 89}  //weight: 5, accuracy: High
        $x_1_3 = {45 6e 74 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GPX_2147924451_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GPX!MTB"
        threat_id = "2147924451"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 10 89 d1 f6 d1 89 c8 41 89 c8 88 8d 00}  //weight: 5, accuracy: High
        $x_2_2 = {40 30 f1 08 d1 89 ca 80 f2 01 20 d1 89 d3 20 cb 30 d1 08 d9}  //weight: 2, accuracy: High
        $x_1_3 = {45 6e 74 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_ASQ_2147926889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.ASQ!MTB"
        threat_id = "2147926889"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 83 ec 20 41 b8 00 30 00 00 41 b9 40 00 00 00 31 c9}  //weight: 2, accuracy: High
        $x_2_2 = {48 83 c4 20 48 89 45}  //weight: 2, accuracy: High
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GTT_2147926982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GTT!MTB"
        threat_id = "2147926982"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 b8 00 30 00 00 41 b9 40 00 00 00 31 c9 [0-1] ff}  //weight: 10, accuracy: Low
        $x_1_2 = "%s%s\\key4.db" ascii //weight: 1
        $x_1_3 = "/up.php" ascii //weight: 1
        $x_1_4 = "\\Thunderbird\\Profiles\\" ascii //weight: 1
        $x_1_5 = "%s%s\\logins.json" ascii //weight: 1
        $x_1_6 = "/c systeminfo >" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GA_2147927841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GA!MTB"
        threat_id = "2147927841"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 0f b6 6c 38 04 43 0f b6 8c 3b 04 04 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {89 cb f6 d3 08 da 80 e3 ec 80 e1 13 08 d9 30 c1 f6 d2 08 ca 44 89 e0 f6 d0 20 d0 f6 d2 44 20 e2 08 c2 43 88 94 3b 04 04 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 44 24 30 07 04 0a 04 41 b8 04 01 00 00 c7 44 24 34 0a 0c 03 04 48 8d 8c 24 50 01 00 00 c7 44 24 38 2d 04 10 04 c7 44 24 3c 15 04 22 04}  //weight: 1, accuracy: High
        $x_1_4 = {44 8b c7 4c 8d 1d 50 78 01 00 44 8b d0 4c 8b cb 66 66 0f 1f 84 00 00 00 00 00 33 d2 4d 8d 49 01 41 8b c0 41 ff c0 41 f7 f2 42 0f b6 0c 1a 41 30 49 ff 44 3b c6 72 e3}  //weight: 1, accuracy: High
        $x_1_5 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GN_2147928229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GN!MTB"
        threat_id = "2147928229"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f 94 c1 30 cb 80 f3 01 89 da 20 ca 30 cb 08 d3}  //weight: 2, accuracy: High
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_NSB_2147929010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.NSB!MTB"
        threat_id = "2147929010"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "@mbaITmj]ZtGEfI[EEdtghzhjnVDuNtE_EDea" ascii //weight: 2
        $x_1_2 = "Yz]hJVaoKI[g}AmOezfXVVK|HOeaYV]TAT\\EY@" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "Ak]ETmFHGXhNmFdj" ascii //weight: 1
        $x_1_5 = "fnAti[t\\Hmav" ascii //weight: 1
        $x_1_6 = "yYnGNxeMh{fgoxETJ{fbeJtza\\YccxNEmxnhhYvaI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GF_2147929473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GF!MTB"
        threat_id = "2147929473"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 01 c8 49 29 c1 41 8a 04 24 41 88 03 44 8b 2d f5 ea 05 00 41 8d 75 ff 41 0f af f5}  //weight: 3, accuracy: High
        $x_2_2 = {30 c1 f6 c1 01 0f 85}  //weight: 2, accuracy: High
        $x_4_3 = {89 d0 20 c8 30 d1 08 c1 44 89 c0 30 c8 34 01 20 c8 44 08 c1 34 01 89 c2 30 ca}  //weight: 4, accuracy: High
        $x_1_4 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_A_2147935982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.A!MTB"
        threat_id = "2147935982"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 d0 35 e9 60 ea ?? 81 f2 16 9f 05 61 41 89 c9 41 81 e1 10 9d 10 6f 41 81 e2 ef 62 ef ?? 45 09 ca 09 d1 81 e2 10 9d 10 6f 25 ef 62 ef ?? 09 d0 44 31 d0}  //weight: 2, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_GVA_2147936310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.GVA!MTB"
        threat_id = "2147936310"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "IMAP Server" ascii //weight: 1
        $x_1_2 = "IMAP User" ascii //weight: 1
        $x_1_3 = "/up.php" ascii //weight: 1
        $x_1_4 = "\\logins.json" ascii //weight: 1
        $x_1_5 = "IMAP Password" ascii //weight: 1
        $x_1_6 = "\\key4.db" ascii //weight: 1
        $x_1_7 = "cheollima" ascii //weight: 1
        $x_1_8 = "\\Thunderbird\\Profiles\\" ascii //weight: 1
        $x_3_9 = {39 34 2e 31 35 39 2e 31 31 33 2e [0-3] 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StrelaStealer_PGS_2147940182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StrelaStealer.PGS!MTB"
        threat_id = "2147940182"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "mkhViulPiqHHOEocCvVciLqRTwkgwGHcgRTBlPKkkAxFVLqMHzFlfCAAbgSacgxeBLbMyapxQwMT" ascii //weight: 3
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

