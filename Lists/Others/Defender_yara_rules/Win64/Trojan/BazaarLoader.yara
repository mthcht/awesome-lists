rule Trojan_Win64_BazaarLoader_CCGN_2147900619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazaarLoader.CCGN!MTB"
        threat_id = "2147900619"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazaarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 f9 48 c7 c2 04 00 00 00 49 c7 c0 ?? ff ff ff 49 81 c0 ?? ?? ?? ?? 6a 00 6a 00 4c 8d 0c 24 c8 60 00 00 ff 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazaarLoader_CCGG_2147900752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazaarLoader.CCGG!MTB"
        threat_id = "2147900752"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazaarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Global\\AlreadyExist" ascii //weight: 1
        $x_1_2 = "os_version\":\"%s" ascii //weight: 1
        $x_1_3 = "win_id\":\"%s" ascii //weight: 1
        $x_1_4 = "client_version\":%f" ascii //weight: 1
        $x_1_5 = "task_id" ascii //weight: 1
        $x_1_6 = "System\\xxx1.bak" ascii //weight: 1
        $x_1_7 = "Add-MpPreference -ExclusionPath c:\\windows" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazaarLoader_OBS_2147917301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazaarLoader.OBS!MTB"
        threat_id = "2147917301"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazaarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 44 24 30 48 8b 00 8b 40 28 48 8b 4c 24 40 48 03 c8 48 8b c1 48 89 84 24 a0 00 00 00 45 33 c0 ba 01 00 00 00 48 b9 00 00 00 80 01 00 00 00 ff 94 24 a0 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazaarLoader_MKV_2147918658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazaarLoader.MKV!MTB"
        threat_id = "2147918658"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazaarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 03 d6 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 ?? 48 2b c8 49 2b cb 8a 44 0c 20 42 32 04 0b 41 88 01 4c 03 ce 45 3b d4 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazaarLoader_TSC_2147922436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazaarLoader.TSC!MTB"
        threat_id = "2147922436"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazaarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 03 cc 48 f7 e1 48 c1 ea 04 48 6b c2 ?? 48 2b c8 8a 44 0c 20 43 32 04 13 41 88 02 4d 03 d4 44 3b cb 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazaarLoader_TSP_2147922553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazaarLoader.TSP!MTB"
        threat_id = "2147922553"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazaarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 03 cd 48 f7 e1 48 c1 ea ?? 48 6b c2 16 48 2b c8 8a 44 0c 20 43 32 04 1a 41 88 03 4d 03 dd 44 3b cb 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazaarLoader_FOR_2147923105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazaarLoader.FOR!MTB"
        threat_id = "2147923105"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazaarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 74 24 10 48 89 7c 24 18 48 63 41 3c 8b f2 33 d2 44 8b 84 08 88 00 00 00 4c 8b c9 4c 03 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

