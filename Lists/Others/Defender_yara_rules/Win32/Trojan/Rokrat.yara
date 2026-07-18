rule Trojan_Win32_Rokrat_A_2147913232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rokrat.A"
        threat_id = "2147913232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rokrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--wwjaughalvncjwiajs--" ascii //weight: 1
        $x_1_2 = "https://api.pcloud.com" ascii //weight: 1
        $x_1_3 = "Content-Type: voice/mp3" ascii //weight: 1
        $x_1_4 = "dir /A /S %s >>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rokrat_GVA_2147973671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rokrat.GVA!MTB"
        threat_id = "2147973671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rokrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 8a 09 48 8b da 8b 51 01 48 83 c1 05 85 d2 74 12 48 8b c1 44 8b c2 44 30 08 48 ff c0 49 83 e8 01 75 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rokrat_GVB_2147973672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rokrat.GVB!MTB"
        threat_id = "2147973672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rokrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 51 bf 66 83 fa 19 77 04 66 83 c1 20 49 83 c0 02 0f b7 c1 41 33 c1 44 69 c8 93 01 00 01 41 0f b7 08 66 85 c9 75 d9}  //weight: 1, accuracy: High
        $x_1_2 = {42 0f b6 04 01 34 f9 88 01 48 8d 49 01 48 83 ea 01 75 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rokrat_GVC_2147973673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rokrat.GVC!MTB"
        threat_id = "2147973673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rokrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 85 10 02 00 00 38 02 00 00 33 d2 8d 4a 02 ff 15 5b fa 02 00 48 8b f0 48 83 f8 ff 0f 84 80 00 00 00 48 8d 95 10 02 00 00 48 8b ce ff 15 46 fa 02 00 85 c0 74 6c 44 8b 85 18 02 00 00 33 d2 b9 ff ff 1f 00 ff 15 1e fa 02 00 48 8b f8 48 85 c0 74 d0}  //weight: 1, accuracy: High
        $x_1_2 = "EMBED_PAYLOAD_v2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

