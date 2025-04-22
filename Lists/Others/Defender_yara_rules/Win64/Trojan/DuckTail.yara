rule Trojan_Win64_DuckTail_LKA_2147899305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DuckTail.LKA!MTB"
        threat_id = "2147899305"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DuckTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "https://(.*?).serveo.net" wide //weight: 10
        $x_10_2 = "tmp_cap.jpg" wide //weight: 10
        $x_10_3 = "campaign_id" wide //weight: 10
        $x_1_4 = "note.2fa.live/note" wide //weight: 1
        $x_1_5 = "savetext.net/" wide //weight: 1
        $x_1_6 = "adsmanager.facebook.com" wide //weight: 1
        $x_1_7 = "facebook.com/adsmanager" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_DuckTail_ADT_2147903790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DuckTail.ADT!MTB"
        threat_id = "2147903790"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DuckTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 3b 00 75 22 83 0b ff eb 45 45 33 c9 48 8d 15 b6 c4 92 00 41 83 c8 ff 48 8d 0d a3 c4 92 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DuckTail_GTT_2147926754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DuckTail.GTT!MTB"
        threat_id = "2147926754"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DuckTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b5 95 00 d9 95 28 41 8f 69 8f ?? ?? ?? ?? b5 92 1d 96 55 96 25 93 65 92 ed 92 8d 92}  //weight: 10, accuracy: Low
        $x_1_2 = "APEX_TMHupdatingdisabledkey_not_ot_found" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DuckTail_GA_2147932198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DuckTail.GA!MTB"
        threat_id = "2147932198"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DuckTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 89 5d c8 44 89 75 d0 48 8d 4d c8 4c 8d 45 d8 ba 03 02 00 00}  //weight: 3, accuracy: High
        $x_2_2 = {8b c6 8b 4d d8 88 4c 07 10 48 89 7d c0}  //weight: 2, accuracy: High
        $x_1_3 = {48 89 5d c8 44 89 75 d0 48 8d 4d c8}  //weight: 1, accuracy: High
        $x_1_4 = "DotNetRuntimeDebugHeader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DuckTail_GTM_2147939645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DuckTail.GTM!MTB"
        threat_id = "2147939645"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DuckTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {20 50 00 60 0a 00 00 2e 69 64 61 ?? 61 24 35 00 00 00 00 60 ?? 50 00 38 00 00 00 2e 30 30 63 66 ?? 00 00 98 2a 50 ?? 08 00 00 00 2e 43 52 54 24 58}  //weight: 10, accuracy: Low
        $x_1_2 = "APEX_NOWAX_LOADER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

