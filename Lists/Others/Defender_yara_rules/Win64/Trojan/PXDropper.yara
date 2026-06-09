rule Trojan_Win64_PXDropper_C_2147971179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PXDropper.C!MTB"
        threat_id = "2147971179"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PXDropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 8d 2c 34 42 32 6c 36 ?? 48 89 d9 4c 89 f2 4d 89 f8 e8 ?? ?? ?? ?? 40 88 28 4d 89 ee eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PXDropper_CA_2147971189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PXDropper.CA!MTB"
        threat_id = "2147971189"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PXDropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6b 65 72 6e 65 6c 33 32 48 89 07 c7 47 08 2e 64 6c 6c c6 47 0c 00 48 89 f9 ff 15}  //weight: 10, accuracy: High
        $x_10_2 = {6e 74 64 6c 6c 2e 64 6c 48 89 07 66 c7 47 08 6c 00 48 89 f9 ff}  //weight: 10, accuracy: High
        $x_10_3 = {43 72 65 61 74 65 46 69 4c 89 20 c7 40 08 6c 65 57 00 48 89 f1 48 89 c2 ff 15}  //weight: 10, accuracy: High
        $x_1_4 = "Windows Defender\\\\ExclusionTerminateProcessCloseServiceHand" ascii //weight: 1
        $x_1_5 = "ContrVulnerableDriverBlocklistEnable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

