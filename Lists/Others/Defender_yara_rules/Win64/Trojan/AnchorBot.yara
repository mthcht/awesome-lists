rule Trojan_Win64_AnchorBot_B_2147766835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AnchorBot.B!MTB"
        threat_id = "2147766835"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AnchorBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 02 83 f0 ?? 88 45 ?? 8b 45 ?? 04 03 83 f0 ?? 88 45 ?? 8b 45 ?? 04 04 83 f0 ?? 88 45 ?? 8b 45 ?? 04 05 33 c6 88 45 ?? 8b 45 ?? 04 06 83 f0 ?? 88 45 ?? 8b 45 ?? 04 07 83 f0 ?? 88 45 ?? 8b 45 ?? 04 08 83 f0 ?? 88 45 ?? 8b 45 ?? 04 09 83 f0 ?? 88 45}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 4c 15 ?? 83 e9 ?? 88 4c 15 ?? 49 03 d7 48 83 fa ?? 72 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {0f be c8 8b c2 33 c1 42 88 44 0d ?? 4d 03 cf 49 83 f9 ?? 72 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AnchorBot_G_2147766880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AnchorBot.G!MSR"
        threat_id = "2147766880"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AnchorBot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "simsim\\anchorDNS.v5\\Bin\\x64\\Release\\anchorDNS_x64.pdb" ascii //weight: 2
        $x_1_2 = "xwpwpp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

