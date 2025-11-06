rule Trojan_Win64_WarmCookie_CCJH_2147918885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WarmCookie.CCJH!MTB"
        threat_id = "2147918885"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WarmCookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 03 c8 48 8b c1 0f b6 00 0f b6 4c 24 20 48 8b 54 24 40 0f b6 4c 0a 02 33 c1 48 8b 4c 24 28 48 8b 54 24 50 48 03 d1 48 8b ca 88 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_WarmCookie_DA_2147923257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WarmCookie.DA!MTB"
        threat_id = "2147923257"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WarmCookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 0f be 54 0a 01 42 0f be 74 0a 02 41 c1 e2 02 c1 fe 06 41 83 e2 3c 83 e6 03 41 09 f2 4d 63 d2 47 8a 14 13 44 88 50 ?? 46 8a 54 0a 02 49 83 c1 03 41 83 e2 3f 47 8a 14 13 44 88 50 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_WarmCookie_MKV_2147924758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WarmCookie.MKV!MTB"
        threat_id = "2147924758"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WarmCookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d2 48 f7 f7 4d 8d 49 01 0f b6 04 32 41 02 c0 02 d8 0f b6 cb 42 0f b6 44 11 ?? 41 88 41 ff 4b 8d 04 0b 46 88 44 11 ?? 48 3d 00 01 00 00 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_WarmCookie_AWM_2147956984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WarmCookie.AWM!MTB"
        threat_id = "2147956984"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WarmCookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 14 01 48 8b 45 10 88 50 01 48 8b 45 10 0f b6 40 01 0f b6 c0 48 63 d0 48 8b 45 10 48 01 d0 48 8d 50 02 48 8b 45 10 0f b6 00 0f b6 c0 48 63 c8 48 8b 45 10 48 01 c8 48 83 c0 02 48 89 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

