rule Trojan_Win64_KiwiStealer_A_2147927946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KiwiStealer.A!MTB"
        threat_id = "2147927946"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KiwiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b c8 49 2b c8 49 8b d0 48 2b d0 49 3b c0 48 0f 43 d1 69 05 8e 35 02 00 80 51 01 00 48 63 c8 48 69 c1 80 96 98 00 48 3b d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KiwiStealer_B_2147927947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KiwiStealer.B!MTB"
        threat_id = "2147927947"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KiwiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 6b c6 28 c7 44 24 3c 00 00 00 00 48 01 e8 44 8b 50 10 8b 50 0c 8b 40 24 4c 29 e2 4c 89 54 24 50 41 89 c1 48 01 d1 41 89 c0 4c 89 d2 41 c1 e9 1f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

