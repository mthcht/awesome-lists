rule Trojan_Win64_Reflo_GMA_2147889330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Reflo.GMA!MTB"
        threat_id = "2147889330"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Reflo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?ReflectiveDllMain@@YAHPEAE@Z" ascii //weight: 1
        $x_1_2 = "\\CRYPTOCOIN\\rootkit\\r77-rootkit-master_1.3.0\\r77-rootkit-master\\vs\\x64\\Release\\r77-x64.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Reflo_NR_2147897387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Reflo.NR!MTB"
        threat_id = "2147897387"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Reflo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 0e 48 39 c3 74 0d b9 ?? ?? ?? ?? ff d6 eb e8 31 f6 eb 05 be ?? ?? ?? ?? 48 8b 1d 2e 3f 57 00 8b 03 ff c8 75 0c}  //weight: 5, accuracy: Low
        $x_1_2 = "Bewbodfe!Njdsp!Efwjdft" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Reflo_HNS_2147905607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Reflo.HNS!MTB"
        threat_id = "2147905607"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Reflo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {eb 17 41 89 c2 41 83 e2 1f 45 32 0c 12 44 88 0c 07 48 ff c0 48 39 c6 74 ac 44 0f b6 0c 07 45 84 c0 74 df}  //weight: 2, accuracy: High
        $x_2_2 = {48 89 78 18 48 c7 40 28 00 00 06 00 48 c7 40 30 08 00 00 00 48 8b 4c 24 58}  //weight: 2, accuracy: High
        $x_2_3 = "BQ8jggZci8dcigdaHZiQHZgk" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Reflo_AHB_2147949113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Reflo.AHB!MTB"
        threat_id = "2147949113"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Reflo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {e1 49 c1 f9 ?? 4d 21 e9 44 8b 7c 24 7c 4c 89 e6 4c 8b a4 24 30 02 00 00 4d 01 e7 4c 89 ff 49 f7 df 4d 29 ea 4c 8b ac 24 b8 03}  //weight: 10, accuracy: Low
        $x_5_2 = {49 89 01 48 8b 74 24 68 48 83 c6 ?? 48 83 c7 ?? 4c 8b 84 24 88 00 00 00 48 8b 44 24 58 48 8b 54 24 70}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Reflo_GVA_2147952893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Reflo.GVA!MTB"
        threat_id = "2147952893"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Reflo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c9 74 0a 31 06 01 1e 83 c6 04 49 eb f2}  //weight: 1, accuracy: High
        $x_2_2 = {56 50 53 e8 01 00 00 00 cc 58 89 c3 40 2d 00 ?? 13 00 2d 00 82 0c 10 05 f7 81 0c 10 80 3b cc 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

