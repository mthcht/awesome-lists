rule Trojan_Win64_Bobikstealer_PGSR_2147960085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bobikstealer.PGSR!MTB"
        threat_id = "2147960085"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bobikstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C7x2Kp9QmN4vR8yL1cF6wH3dJ5sB0gT7pV2eZaXu" ascii //weight: 10
        $x_1_2 = "VirtualBox" ascii //weight: 1
        $x_1_3 = "VMware" ascii //weight: 1
        $x_1_4 = "wireshark" ascii //weight: 1
        $x_1_5 = "tcpview" ascii //weight: 1
        $x_1_6 = "processhacker" ascii //weight: 1
        $x_1_7 = "procmon" ascii //weight: 1
        $x_1_8 = "procexp" ascii //weight: 1
        $x_2_9 = "BLOCKED - CIS country detected" ascii //weight: 2
        $x_2_10 = "BLOCKED - VM detected" ascii //weight: 2
        $x_2_11 = "Checking VMware Tools director" ascii //weight: 2
        $x_2_12 = "Killing debuggers" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

