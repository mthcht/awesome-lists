rule Trojan_Win64_CobaltStrikeLoader_LK_2147845674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikeLoader.LK!MTB"
        threat_id = "2147845674"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b d8 48 85 c0 74 10 ba e8 03 00 00 48 8b cb ff 15 ?? ?? 00 00 eb f0 48 83 c4 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrikeLoader_LKX_2147846345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikeLoader.LKX!MTB"
        threat_id = "2147846345"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 28 40 00 00 00 48 ?? ?? ?? ?? 49 0f 45 ff c7 44 24 ?? 00 10 00 00 45 33 c0 49 8b ce ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 ea 80 e2 3f 80 ca 80 41 88 12 4d 8b 13 49 ff c2 4d 89 13 85 c0 7f dc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrikeLoader_LKY_2147846771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikeLoader.LKY!MTB"
        threat_id = "2147846771"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 1f 03 d0 [0-32] 42 8a 8c ?? ?? ?? ?? ?? 43 32 8c ?? ?? ?? ?? ?? 48 8b 85 ?? ?? ?? ?? 41 88 0c ?? 44 03 cf 4c 03 ?? 44 3b 8d ?? ?? 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrikeLoader_LKZ_2147847069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikeLoader.LKZ!MTB"
        threat_id = "2147847069"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 1f 30 03 48 ff c3 48 83 e9 01 75 [0-32] 41 b9 04 00 00 00 41 b8 00 10 00 00 49 8d 56 0a 33 c9 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrikeLoader_LKAA_2147848136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikeLoader.LKAA!MTB"
        threat_id = "2147848136"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 0f b6 0c 02 [0-32] 41 31 c9 44 88 cb [0-12] 41 88 1c 30 ?? ?? ?? 83 c0 01 89 45 cc e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrikeLoader_LKAB_2147848137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikeLoader.LKAB!MTB"
        threat_id = "2147848137"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 45 33 c9 45 33 c0 ba 00 00 00 40 48 8b c8}  //weight: 1, accuracy: High
        $x_1_2 = {4c 8d 8c 24 80 01 00 00 41 b8 00 10 00 00 48 8d 94 24 60 03 00 00 48 8b 4c 24 50}  //weight: 1, accuracy: High
        $x_1_3 = "test1\\source\\repos\\download\\x64\\Release\\download.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrikeLoader_LKAL_2147888310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikeLoader.LKAL!MTB"
        threat_id = "2147888310"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MACOSX\\pdf.pdf" ascii //weight: 1
        $x_1_2 = "updatesanfor.s3-us-east-1.ossfiles.com/javaListen" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrikeLoader_LKAN_2147888313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikeLoader.LKAN!MTB"
        threat_id = "2147888313"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sync.(*RHe0UcdpHEv).RUnlock" ascii //weight: 1
        $x_1_2 = "nX0mgbuOjw.(*wU6_Xfv4).bqwSOvr5m" ascii //weight: 1
        $x_1_3 = "yCcdI7eVq.(*UE5TRl).xKFXpU5Cyab" ascii //weight: 1
        $x_1_4 = "PT2MtVR9gr5.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

