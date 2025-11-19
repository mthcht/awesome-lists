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

rule Trojan_Win64_XLoader_GVC_2147957625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XLoader.GVC!MTB"
        threat_id = "2147957625"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b f0 8b cb 0f b6 44 0d 10 40 0f b6 d6 2b c2 05 00 01 00 00 0f b6 c0 88 44 0d 10 ff c3 3b fb 7f d8}  //weight: 2, accuracy: High
        $x_1_2 = {0f b7 c1 8b c8 c1 f9 02 33 c8 8b d0 c1 fa 03 33 ca 8b d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XLoader_RR_2147957783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XLoader.RR!MTB"
        threat_id = "2147957783"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 c6 04 11 ff 48 c1 e9 0a 48 03 0d f0 b0 18 00 80 39 ff}  //weight: 1, accuracy: High
        $x_1_2 = {4c 63 d2 46 0f b6 0c 11 46 88 0c 10 ff c2 4c 63 d2 4d 3b d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

