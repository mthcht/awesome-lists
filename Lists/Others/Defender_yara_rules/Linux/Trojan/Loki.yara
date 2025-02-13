rule Trojan_Linux_Loki_A_2147835458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Loki.A"
        threat_id = "2147835458"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Loki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/stat" ascii //weight: 2
        $x_2_2 = "/swapt" ascii //weight: 2
        $x_2_3 = "/quit" ascii //weight: 2
        $x_5_4 = "requested a protocol swap" ascii //weight: 5
        $x_5_5 = "requested an all kill" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Loki_B_2147835459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Loki.B"
        threat_id = "2147835459"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Loki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "lokid: server is currently at capacity" ascii //weight: 2
        $x_2_2 = "lokid: Cannot add key" ascii //weight: 2
        $x_2_3 = "lokid -p (i|u)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Linux_Loki_C_2147845534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Loki.C"
        threat_id = "2147845534"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Loki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b 05 ee 42 00 00 41 83 f8 01 0f 84 ?? ?? 00 00 41 83 f8 11 0f 84 ?? ?? 00 00 8b 4c 24 04 b8 00 54 00 00 [0-5] 44 88 05 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 45 89 0d ?? ?? ?? ?? 66 89 05 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 40}  //weight: 1, accuracy: Low
        $x_1_2 = {41 ba 00 35 00 00 bd 00 40 00 00 44 0f b7 1d ?? ?? ?? ?? be 40 00 00 00 48 8d 3d ?? ?? ?? ?? 66 44 89 15 ?? ?? ?? ?? 66 44 89 1d ?? ?? ?? ?? 66 89 2d ?? ?? ?? ?? e8 ?? ?? ?? ?? 44 8b 05 ?? ?? ?? ?? 66 89 05 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_3 = {be 01 f0 ff ff 31 d2 48 8d 3d ?? ?? ?? ?? 66 89 35 ?? ?? ?? ?? be 40 00 00 00 66 89 15 ?? ?? ?? ?? 66 89 1d ?? ?? ?? ?? e8 ?? ?? ?? ?? 44 8b 05 ?? ?? ?? ?? 66 89 05 ?? ?? ?? ?? e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Loki_D_2147845535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Loki.D"
        threat_id = "2147845535"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Loki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 fb 01 0f 84 ?? ?? 00 00 83 fb 11 74 ?? 44 8b 4c 24 04 41 b8 00 54 00 00 8b 3d 46 25 00 00 31 c9 66 44 89 05 ?? ?? ?? ?? ba 54 00 00 00 49 89 e0 48 8d 35 ?? ?? ?? ?? 44 89 0d ?? ?? ?? ?? 41 b9 10 00 00 00 c6 05 ?? ?? ?? ?? 45 c6 05 ?? ?? ?? ?? 40 88 1d}  //weight: 1, accuracy: Low
        $x_1_2 = {be 40 00 00 00 48 8d 3d ?? ?? ?? ?? 66 44 89 25 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 35 00 40 40 88 2d ?? ?? ?? ?? e8 ?? ?? ?? ?? 66 89 05 ?? ?? ?? ?? e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {be 01 f0 ff ff ba 08 00 00 00 48 8d 3d ?? ?? ?? ?? 66 44 89 25 ?? ?? ?? ?? 66 89 35 ?? ?? ?? ?? be 40 00 00 00 66 89 15 ?? ?? ?? ?? 40 88 2d ?? ?? ?? ?? e8 ?? ?? ?? ?? 66 89 05 ?? ?? ?? ?? e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

