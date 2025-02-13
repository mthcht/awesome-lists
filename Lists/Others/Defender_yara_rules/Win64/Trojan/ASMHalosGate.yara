rule Trojan_Win64_ASMHalosGate_PC_2147853385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ASMHalosGate.PC!MTB"
        threat_id = "2147853385"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ASMHalosGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 f1 8b c2 8b c0 48 8d 0d 2e 2c 00 00 8b 54 24 54 33 14 81 8b c2 8b 4c 24 30 48 8b 54 24 40 88 04 0a}  //weight: 1, accuracy: High
        $x_1_2 = "bcookesHalosGate.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

