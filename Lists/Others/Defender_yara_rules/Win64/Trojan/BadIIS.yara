rule Trojan_Win64_BadIIS_SX_2147964607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BadIIS.SX!MTB"
        threat_id = "2147964607"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BadIIS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 85 c0 74 ?? 48 8d ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? 48 89 ?? 45 33 c9 48 8b ?? 41 b8 01 00 00 00 [0-7] 48 8b cb 48 83 c4 20}  //weight: 20, accuracy: Low
        $x_10_2 = {48 c7 c3 ff ff ff ff 48 89 45 ?? 0f 11 44 24 ?? c7 44 24 ?? 68 00 00 00 48 8b d3 0f 11 44 24 ?? c7 44 24 ?? ff ff ff ff}  //weight: 10, accuracy: Low
        $x_3_3 = "x-real-ip: %s" ascii //weight: 3
        $x_2_4 = "\\SearchEngine" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BadIIS_MK_2147971034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BadIIS.MK!MTB"
        threat_id = "2147971034"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BadIIS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_35_1 = {48 8b 44 24 68 48 8b 00 45 33 c9 41 b8 01 00 00 20 48 8b 54 24 28 48 8b 4c 24 68 ff 50 10 89 44 24 20 83 7c 24 20}  //weight: 35, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BadIIS_GVA_2147975748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BadIIS.GVA!MTB"
        threat_id = "2147975748"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BadIIS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c2 83 e0 3f 48 8b da 48 33 1d 55 f8 01 00 8b c8 48 d3 cb b9 40 00 00 00 2b c8 48 d3 cf 48 33 fa 48 89 3d 3c f8 01 00 33 c9}  //weight: 1, accuracy: High
        $x_1_2 = "SERVER_NAME" ascii //weight: 1
        $x_1_3 = "REMOTE_ADDR" ascii //weight: 1
        $x_1_4 = "360browser" ascii //weight: 1
        $x_1_5 = "qqbrowser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

