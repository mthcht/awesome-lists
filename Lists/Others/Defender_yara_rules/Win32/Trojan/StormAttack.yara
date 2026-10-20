rule Trojan_Win32_StormAttack_KK_2147970796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StormAttack.KK!MTB"
        threat_id = "2147970796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StormAttack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8a 84 0d 00 fe ff ff 34 2c 88 84 0d 00 fd ff ff 34 02 88 84 0d 00 ff ff ff 41 3b ca}  //weight: 20, accuracy: High
        $x_10_2 = {8d 45 e0 6a 10 50 56 ff 75 f8 8d 45 f0 50 57 ff 15}  //weight: 10, accuracy: High
        $x_5_3 = "Storm DDOS Server" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StormAttack_AT_2147980625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StormAttack.AT!MTB"
        threat_id = "2147980625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StormAttack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StormServer.dll" ascii //weight: 1
        $x_1_2 = "Storm ddos Server" ascii //weight: 1
        $x_1_3 = "Welcome to use storm ddos" ascii //weight: 1
        $x_1_4 = "Thank you" ascii //weight: 1
        $x_1_5 = "/c  del" ascii //weight: 1
        $x_1_6 = "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

