rule Trojan_Win64_Spyboy_AA_2147848158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Spyboy.AA!MTB"
        threat_id = "2147848158"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Spyboy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.connectToZemaDevice" ascii //weight: 1
        $x_1_2 = "main.detectEDR" ascii //weight: 1
        $x_1_3 = "main.loadDriver" ascii //weight: 1
        $x_1_4 = "main.dropDriver" ascii //weight: 1
        $x_1_5 = "main.EnablePrivilege" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Spyboy_AB_2147848159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Spyboy.AB!MTB"
        threat_id = "2147848159"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Spyboy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "103"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 100, accuracy: High
        $x_1_2 = "WmVtYW5hIEx0ZC4xFDASBgNVBAMTC1plbWFuYSBMdGQuMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsMg0" ascii //weight: 1
        $x_1_3 = "6BVJ0bEluaXRVbmljb2RlU3RyaW5nAABRBVJ0bENvcHlVbmljb2RlU3RyaW5nAAA/" ascii //weight: 1
        $x_1_4 = "ASACIAMgBCAFIAYgByAIIAkgCiALIAwgDSAOIACBDyAQIBEgEiATIBQgFSAWIBcg" ascii //weight: 1
        $x_2_5 = {1f 00 e8 69 31 00 00 8b d8 85 ?? ?? ?? 8b 0e 48 8d 05 22 ?? ?? ?? ?? ?? 0d 3b 00 01 00 89 4c 24 30 48 89 44 24 28 48 ?? ?? ?? ?? 00 00 b9 07 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 13 93 ff ff eb 06 8b 44 24 50 89 07 48 8b 74 24 60 8b c3 48 8b 5c}  //weight: 2, accuracy: Low
        $x_2_6 = "\\DosDevices\\ZemanaAntiMalware" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Spyboy_AC_2147850505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Spyboy.AC!MTB"
        threat_id = "2147850505"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Spyboy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\ZemanaAntiMalware" wide //weight: 1
        $x_1_2 = "Terminating ALL EDR/XDR/AVs" ascii //weight: 1
        $x_1_3 = "avast" ascii //weight: 1
        $x_1_4 = "carbonblack" ascii //weight: 1
        $x_1_5 = "crowdstrike" ascii //weight: 1
        $x_1_6 = "cylance" ascii //weight: 1
        $x_1_7 = "defender" ascii //weight: 1
        $x_1_8 = "kaspersky" ascii //weight: 1
        $x_1_9 = "mandiant" ascii //weight: 1
        $x_1_10 = "mcafee" ascii //weight: 1
        $x_1_11 = "palo alto networks" ascii //weight: 1
        $x_1_12 = "sophos" ascii //weight: 1
        $x_1_13 = "symantec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

