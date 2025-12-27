rule Trojan_Win64_Fragtor_A_2147907877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fragtor.A!MTB"
        threat_id = "2147907877"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 ac fe c8 f6 d8 2c ?? c0 c8 ?? 34 ?? fe c8 88 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fragtor_MR_2147947781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fragtor.MR!MTB"
        threat_id = "2147947781"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8b 45 f0 48 8d 50 01 48 89 55 f0 0f b6 10 48 8b 45 f8 48 8d 48 01 48 89 4d f8 88 10 48 83 6d 20 01 48 83 7d 20}  //weight: 10, accuracy: High
        $x_5_2 = {89 45 fc 48 8b 45 10 48 8d 50 01 48 89 55 10 0f b6 00 0f b6 c0 89 45 f8 83 7d f8 00 0f 95 c0 84 c0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fragtor_GVB_2147949111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fragtor.GVB!MTB"
        threat_id = "2147949111"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c7 a3 fc 0c 09 10 8b 44 24 38 8d 04 50 03 d0 8a 81 34 48 00 00 04 10 30 02 ff 01 47 8b 01 8b 54 24 1c 0f b7 44 45 10 3b f8 0f 8e ab fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fragtor_GVF_2147957687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fragtor.GVF!MTB"
        threat_id = "2147957687"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" wide //weight: 2
        $x_1_2 = "Downloaded to Startup: %s" wide //weight: 1
        $x_1_3 = "Self copy failed (admin?)" wide //weight: 1
        $x_1_4 = "www.modedapk.net" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

