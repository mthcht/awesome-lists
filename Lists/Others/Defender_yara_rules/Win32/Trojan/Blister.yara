rule Trojan_Win32_Blister_A_2147815252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blister.A"
        threat_id = "2147815252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blister"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {64 a1 30 00 00 00 53 57 89 75 ?? 8b 40 0c 8b 40 1c}  //weight: 4, accuracy: Low
        $x_4_2 = {8b 48 20 8b 50 1c 03 cb 8b 78 24 03 d3 8b 40 18 03 fb}  //weight: 4, accuracy: High
        $x_4_3 = {c1 c2 09 0f be c0 03 d0 41 8a 01 84 c0}  //weight: 4, accuracy: High
        $x_4_4 = {8b c6 83 e0 03 8a 44 05 ?? 30 04 ?? 46 81 fe}  //weight: 4, accuracy: Low
        $x_4_5 = {50 6a ff ff d7 8d 45 ?? 50 8d 83 ?? ?? ?? ?? ff d0}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Blister_MKZ_2147917192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blister.MKZ!MTB"
        threat_id = "2147917192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blister"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {50 6a ff ff d7 8b c6 83 e0 03 8a 44 05 e8 30 04 1e 46 81 fe e0 89 01 00 72 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blister_TWR_2147920256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blister.TWR!MTB"
        threat_id = "2147920256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blister"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ff d7 8b c6 83 e0 03 8a 44 05 e8 30 04 1e 46 81 fe 50 7a 01 00 72 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blister_RTQ_2147920358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blister.RTQ!MTB"
        threat_id = "2147920358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blister"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b c6 83 e0 03 8a 44 05 e8 30 04 1e 46 81 fe e0 89 01 00 72 eb}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

