rule TrojanSpy_Win64_Banker_XG_2147723338_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Banker.XG"
        threat_id = "2147723338"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 60 81 f1 ?? ?? 00 00 3b c1 75 0b 05 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 04 48 83 f0 ?? 48 8b 4c 24 ?? 48 8b 54 24 ?? 66 89 04 51 eb}  //weight: 1, accuracy: Low
        $x_1_3 = "SELECT * FROM AntiVirusProduct" wide //weight: 1
        $x_1_4 = "ROOT\\SecurityCenter2" wide //weight: 1
        $x_2_5 = "inject_before_keyword" ascii //weight: 2
        $x_2_6 = "inject_after_keyword" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win64_Banker_PADC_2147901396_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Banker.PADC!MTB"
        threat_id = "2147901396"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 f1 78 3b f6 82 80 e2 01 0f 44 c8 8b c1 d1 e8 8b d0 81 f2 78 3b f6 82 80 e1 01 0f 44 d0 8b c2 d1 e8 44 8b c0 41 81 f0 78 3b f6 82 80 e2 01 44 0f 44 c0 41 8b c8 d1 e9 44 8b c9 41 81 f1 78 3b f6 82 41 80 e0 01 44 0f 44 c9 48 83 eb 01 0f 85 51}  //weight: 1, accuracy: High
        $x_1_2 = "Elevation:Administrator!new:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

