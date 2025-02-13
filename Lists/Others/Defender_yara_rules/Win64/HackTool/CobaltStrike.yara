rule HackTool_Win64_CobaltStrike_A_2147763653_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.A"
        threat_id = "2147763653"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 00 01 00 02 ?? ?? 00 02 00 01 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4e 4f 4e 4f 4e 4c ?? ?? 4e 4c 4e 4f 4e 4c}  //weight: 1, accuracy: Low
        $x_1_5 = {4c 63 c2 4d 03 c0 42 0f 10 04 c0 48 8b c1 f3 0f 7f 01 c3}  //weight: 1, accuracy: High
        $x_10_6 = {48 ff c0 48 3d 00 10 00 00 7c f1 04 00 80 ?? ?? 03 01 01 01 2e 69 4e 48}  //weight: 10, accuracy: Low
        $x_10_7 = {0f af d1 44 8b c8 b8 1f 85 eb 51 f7 e2 41 8b c1 44 8b c2 33 d2 41 c1 e8 05 41 f7 f0}  //weight: 10, accuracy: High
        $x_10_8 = {b9 00 00 10 00 e8 [0-60] ba 7f 66 04 40 8b c8 48 8b [0-8] 89 08 48 8b 4b 20}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win64_CobaltStrike_A_2147763654_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.A!!CobaltStrike.A64"
        threat_id = "2147763654"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "A64: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 63 c2 4d 03 c0 42 0f 10 04 c0 48 8b c1 f3 0f 7f 01 c3}  //weight: 1, accuracy: High
        $x_10_5 = {48 ff c0 48 3d 00 10 00 00 7c f1 04 00 80 ?? ?? (2e|69) 48}  //weight: 10, accuracy: Low
        $x_10_6 = {0f af d1 44 8b c8 b8 1f 85 eb 51 f7 e2 41 8b c1 44 8b c2 33 d2 41 c1 e8 05 41 f7 f0}  //weight: 10, accuracy: High
        $x_10_7 = {b9 00 00 10 00 e8 [0-60] ba 7f 66 04 40 8b c8 48 8b [0-8] 89 08 48 8b 4b 20}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win64_CobaltStrike_B_2147776559_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.B!!CobaltStrike.B64"
        threat_id = "2147776559"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "B64: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 63 c2 4d 03 c0 42 0f 10 04 c0 48 8b c1 f3 0f 7f 01 c3}  //weight: 1, accuracy: High
        $x_10_5 = {48 ff c0 48 3d 00 10 00 00 7c f1 04 00 80 ?? ?? (2e|69) 48}  //weight: 10, accuracy: Low
        $n_100_6 = "Behavior:" ascii //weight: -100
        $n_100_7 = "Trojan:" ascii //weight: -100
        $n_100_8 = "mpattribute" ascii //weight: -100
        $n_100_9 = "HackTool:" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win64_CobaltStrike_C_2147776560_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.C!!CobaltStrike.C64"
        threat_id = "2147776560"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "C64: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 63 c2 4d 03 c0 42 0f 10 04 c0 48 8b c1 f3 0f 7f 01 c3}  //weight: 1, accuracy: High
        $x_10_5 = {0f af d1 44 8b c8 b8 1f 85 eb 51 f7 e2 41 8b c1 44 8b c2 33 d2 41 c1 e8 05 41 f7 f0}  //weight: 10, accuracy: High
        $n_100_6 = "Behavior:" ascii //weight: -100
        $n_100_7 = "Trojan:" ascii //weight: -100
        $n_100_8 = "mpattribute" ascii //weight: -100
        $n_100_9 = "HackTool:" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win64_CobaltStrike_D_2147776561_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.D!!CobaltStrike.D64"
        threat_id = "2147776561"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "D64: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 63 c2 4d 03 c0 42 0f 10 04 c0 48 8b c1 f3 0f 7f 01 c3}  //weight: 1, accuracy: High
        $x_10_5 = {b9 00 00 10 00 e8 [0-60] ba 7f 66 04 40 8b c8 48 8b [0-8] 89 08 48 8b 4b 20}  //weight: 10, accuracy: Low
        $n_100_6 = "Behavior:" ascii //weight: -100
        $n_100_7 = "Trojan:" ascii //weight: -100
        $n_100_8 = "mpattribute" ascii //weight: -100
        $n_100_9 = "HackTool:" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win64_CobaltStrike_E_2147776562_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.E!!CobaltStrike.E64"
        threat_id = "2147776562"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "E64: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 27 5b 8b 2b 83 c3 04 8b 13 31 ea 83 c3 04 53 8b 33 31 ee 89 33 31 f5 83 c3 04 83 ea 04 31 f6 39 f2}  //weight: 1, accuracy: High
        $x_1_2 = {eb 33 5d 8b 45 00 48 83 c5 04 8b 4d 00 31 c1 48 83 c5 04 55 8b 55 00 31 c2 89 55 00 31 d0 48 83 c5 04 83 e9 04 31 d2 39 d1}  //weight: 1, accuracy: High
        $n_100_3 = "Behavior:" ascii //weight: -100
        $n_100_4 = "Trojan:" ascii //weight: -100
        $n_100_5 = "mpattribute" ascii //weight: -100
        $n_100_6 = "HackTool:" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule HackTool_Win64_CobaltStrike_B_2147777018_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.B"
        threat_id = "2147777018"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4e 4f 4e 4f 4e 4c ?? ?? 4e 4c 4e 4f 4e 4c}  //weight: 1, accuracy: Low
        $x_1_5 = {4c 63 c2 4d 03 c0 42 0f 10 04 c0 48 8b c1 f3 0f 7f 01 c3}  //weight: 1, accuracy: High
        $x_10_6 = {48 ff c0 48 3d 00 10 00 00 7c f1 04 00 80 ?? ?? 03 01 01 01 2e 69 4e 48}  //weight: 10, accuracy: Low
        $n_100_7 = "Behavior:" ascii //weight: -100
        $n_100_8 = "Trojan:" ascii //weight: -100
        $n_100_9 = "mpattribute" ascii //weight: -100
        $n_100_10 = "HackTool:" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win64_CobaltStrike_C_2147777019_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.C"
        threat_id = "2147777019"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4e 4f 4e 4f 4e 4c ?? ?? 4e 4c 4e 4f 4e 4c}  //weight: 1, accuracy: Low
        $x_1_5 = {4c 63 c2 4d 03 c0 42 0f 10 04 c0 48 8b c1 f3 0f 7f 01 c3}  //weight: 1, accuracy: High
        $x_10_6 = {0f af d1 44 8b c8 b8 1f 85 eb 51 f7 e2 41 8b c1 44 8b c2 33 d2 41 c1 e8 05 41 f7 f0}  //weight: 10, accuracy: High
        $n_100_7 = "Behavior:" ascii //weight: -100
        $n_100_8 = "Trojan:" ascii //weight: -100
        $n_100_9 = "mpattribute" ascii //weight: -100
        $n_100_10 = "HackTool:" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win64_CobaltStrike_D_2147777020_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.D"
        threat_id = "2147777020"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4e 4f 4e 4f 4e 4c ?? ?? 4e 4c 4e 4f 4e 4c}  //weight: 1, accuracy: Low
        $x_1_5 = {4c 63 c2 4d 03 c0 42 0f 10 04 c0 48 8b c1 f3 0f 7f 01 c3}  //weight: 1, accuracy: High
        $x_10_6 = {b9 00 00 10 00 e8 [0-60] ba 7f 66 04 40 8b c8 48 8b [0-8] 89 08 48 8b 4b 20}  //weight: 10, accuracy: Low
        $n_100_7 = "Behavior:" ascii //weight: -100
        $n_100_8 = "Trojan:" ascii //weight: -100
        $n_100_9 = "mpattribute" ascii //weight: -100
        $n_100_10 = "HackTool:" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win64_CobaltStrike_E_2147777021_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.E"
        threat_id = "2147777021"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 27 5b 8b 2b 83 c3 04 8b 13 31 ea 83 c3 04 53 8b 33 31 ee 89 33 31 f5 83 c3 04 83 ea 04 31 f6 39 f2}  //weight: 1, accuracy: High
        $x_1_2 = {eb 33 5d 8b 45 00 48 83 c5 04 8b 4d 00 31 c1 48 83 c5 04 55 8b 55 00 31 c2 89 55 00 31 d0 48 83 c5 04 83 e9 04 31 d2 39 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_Win64_CobaltStrike_F_2147784077_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.F!!CobaltStrike.F64"
        threat_id = "2147784077"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "F64: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 4f ec c4 4e 41 f7 e1 41 8b c1 c1 ea 02 41 ff c1 6b d2 0d 2b c2 8a 4c 18 10 41 30 0c 38}  //weight: 1, accuracy: High
        $x_1_2 = {31 d2 4c 8b ?? 41 f7 f1 49 01 cb 48 ff c1 89 d0 8a 44 03 10 41 30 03}  //weight: 1, accuracy: Low
        $n_100_3 = "Behavior:" ascii //weight: -100
        $n_100_4 = "Trojan:" ascii //weight: -100
        $n_100_5 = "mpattribute" ascii //weight: -100
        $n_100_6 = "HackTool:" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule HackTool_Win64_CobaltStrike_F_2147797950_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.F"
        threat_id = "2147797950"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 4f ec c4 4e 41 f7 e1 41 8b c1 c1 ea 02 41 ff c1 6b d2 0d 2b c2 8a 4c 18 10 41 30 0c 38}  //weight: 1, accuracy: High
        $x_1_2 = {31 d2 4c 8b ?? 41 f7 f1 49 01 cb 48 ff c1 89 d0 8a 44 03 10 41 30 03}  //weight: 1, accuracy: Low
        $n_100_3 = "Behavior:" ascii //weight: -100
        $n_100_4 = "Trojan:" ascii //weight: -100
        $n_100_5 = "mpattribute" ascii //weight: -100
        $n_100_6 = "HackTool:" ascii //weight: -100
        $n_100_7 = {7f 00 00 18 00 00 00 00 00 00 00 ff ff ff ff}  //weight: -100, accuracy: High
        $n_100_8 = {f7 7f 00 00 2a 00 00 00 00 00 00 00 ff ff ff ff}  //weight: -100, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule HackTool_Win64_CobaltStrike_G_2147798574_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.G"
        threat_id = "2147798574"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_CobaltStrike_G_2147798577_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.G!!CobaltStrike.G64"
        threat_id = "2147798577"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "G64: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_CobaltStrike_H_2147811539_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.H"
        threat_id = "2147811539"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 5a 41 52 55 48 89 e5 48 81 ec 20 00 00 00 48 8d 1d ea ff ff ff 48 89 df 48 81 c3 ?? ?? ?? ?? ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_CobaltStrike_I_2147844521_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.I"
        threat_id = "2147844521"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 63 c0 48 03 c0 0f 10 04 c2 48 8b c1 f3 0f 7f 01 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b d1 48 8b 0d ?? ?? ?? ?? e9 ?? ?? ff ff cc cc 8b d1 48 8b 0d ?? ?? ?? ?? e9 ?? ?? ff ff cc cc 8b d1 48 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_CobaltStrike_K_2147902163_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.K"
        threat_id = "2147902163"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 f7 e1 41 8b c1 c1 ea 02 41 ff c1 6b d2 0d 2b c2}  //weight: 1, accuracy: High
        $x_1_2 = {4c 8b 19 41 f7 f2 4d 01 cb 49 ff c1 89 d0 8a 44 01 18 41 30 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_Win64_CobaltStrike_I_2147902926_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.I!!CobaltStrike.I64"
        threat_id = "2147902926"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "I64: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 63 c0 48 03 c0 0f 10 04 c2 48 8b c1 f3 0f 7f 01 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b d1 48 8b 0d ?? ?? ?? ?? e9 ?? ?? ff ff cc cc 8b d1 48 8b 0d ?? ?? ?? ?? e9 ?? ?? ff ff cc cc 8b d1 48 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_CobaltStrike_K_2147902928_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.K!!CobaltStrike.K64"
        threat_id = "2147902928"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "K64: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 f7 e1 41 8b c1 c1 ea 02 41 ff c1 6b d2 0d 2b c2}  //weight: 1, accuracy: High
        $x_1_2 = {4c 8b 19 41 f7 f2 4d 01 cb 49 ff c1 89 d0 8a 44 01 18 41 30 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_Win64_CobaltStrike_CP_2147910252_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.CP!ldr"
        threat_id = "2147910252"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 53 6f 70 68 6f 73 55 6e 69 6e 73 74 61 6c 6c 2e 70 ?? 62}  //weight: 1, accuracy: Low
        $x_1_2 = {53 6f 70 68 6f 73 46 53 2e 70 ?? 62}  //weight: 1, accuracy: Low
        $x_1_3 = {00 53 6f 70 68 6f 73 4e 74 70 55 6e 69 6e 73 74 61 6c 6c 2e 70 ?? 62}  //weight: 1, accuracy: Low
        $x_1_4 = {00 53 6f 70 68 6f 73 46 53 54 65 6c 65 6d 65 74 72 79 2e 70 ?? 62}  //weight: 1, accuracy: Low
        $x_3_5 = {80 cc 10 41 89 c2 8b 85}  //weight: 3, accuracy: High
        $x_3_6 = {01 d0 80 cc 10 41 89 c2}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win64_CobaltStrike_CR_2147914814_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.CR!ldr"
        threat_id = "2147914814"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 d7 c1 c2 07 87 c7 33 c2 f7 d0 c1 c1 12 87 ?? 87 c2 4b f7 da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_CobaltStrike_CQ_2147915150_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CobaltStrike.CQ!ldr"
        threat_id = "2147915150"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 5c 08 18 48 8d 04 92 48 8d 2c c3 eb}  //weight: 1, accuracy: High
        $x_1_2 = {44 89 ef 45 31 c9 45 31 c0 48 83 c7 22 31 d2 4c 89 e1 4c 8b 7c fd 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

