rule Trojan_Win64_ClearFake_YAA_2147920970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClearFake.YAA!MTB"
        threat_id = "2147920970"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClearFake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 45 e3 48 31 45 92 89 55 84 28 75 f1 b9}  //weight: 1, accuracy: High
        $x_1_2 = {44 30 27 48 8d 05 ?? ?? ?? ?? 50 53 57 56 41 55 41 54 55 48 89 e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClearFake_NA_2147921847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClearFake.NA!MTB"
        threat_id = "2147921847"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClearFake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {cc cc cc cc cc cc 48 83 fe 00 75 01 c3 44 30 27 48 8d 05 ?? ?? 00 00}  //weight: 5, accuracy: Low
        $x_3_2 = {cc cc cc 48 ff c7 48 ff ce e9 ?? ?? ff ff}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClearFake_NB_2147921848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClearFake.NB!MTB"
        threat_id = "2147921848"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClearFake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 83 fe 00 75 01 c3 44 30 27 48 8d 05 ?? ?? 00 00}  //weight: 5, accuracy: Low
        $x_3_2 = {48 ff c7 48 ff ce e9 ?? ?? ff ff}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClearFake_B_2147927455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClearFake.B"
        threat_id = "2147927455"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClearFake"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c9 0f 31 48 c1 e2 20 48 09 c2 48 39 da 0f ?? ?? ?? ?? ?? 48 89 d9 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

