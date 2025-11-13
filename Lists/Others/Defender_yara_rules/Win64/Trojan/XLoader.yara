rule Trojan_Win64_XLoader_GVA_2147954704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XLoader.GVA!MTB"
        threat_id = "2147954704"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d1 48 8d 44 10 10 0f b6 00 48 8b 4d c0 30 01 8b 45 d8 ff c0 89 45 d8 8b 45 d8 3b 45 dc 0f 9c c0 0f b6 c0 89 45 d4 83 7d d4 00 75 a3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XLoader_ACIB_2147955205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XLoader.ACIB!MTB"
        threat_id = "2147955205"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b d1 48 8d 44 10 10 0f b6 00 48 8b 4d c0 30 01 8b 45 d4 ff c0 89 45 d4 8b 45 d4 3b 45 f4 0f 9c c0 0f b6 c0 89 45 d0 83 7d d0 00 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XLoader_MKV_2147955509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XLoader.MKV!MTB"
        threat_id = "2147955509"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {44 8b d2 46 0f b6 54 10 ?? 45 30 10 ff c2 3b d1 7c}  //weight: 4, accuracy: Low
        $x_5_2 = {44 8b d0 41 c1 ea 0c c1 e0 14 41 0b c2 89 02 8b 01 03 02 03 44 24 ?? 89 01 8b 01 41 31 01 41 8b 01 8b c8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XLoader_AKQ_2147957467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XLoader.AKQ!MTB"
        threat_id = "2147957467"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 8b d2 47 0f b6 54 17 10 45 30 10 ff c2 3b d1 7c e0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

