rule Trojan_Linux_Getshell_G_2147794533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Getshell.G!xp"
        threat_id = "2147794533"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Getshell"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 29 58 99 6a 02 5f 6a 01 5e 0f 05 48 97 52 c7 04 24 ?? ?? ?? ?? 48 89 e6 6a 10 5a 6a 31 58 0f 05 6a 32 58 0f 05 48 31 f6 6a 2b 58 0f 05 48 97 6a 03 5e 48 ff ce 6a 21 58 0f 05 75 f6 6a 3b 58 99 48 bb 2f 62 69 6e 2f 73 68 00 53 48 89 e7 52 57 48 89 e6 0f 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Getshell_D_2147923943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Getshell.D!MTB"
        threat_id = "2147923943"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Getshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 e0 99 03 d0 ff bd 27 2c 00 bf af 28 00 b4 af 24 00 b3 af 20 00 b2 af 1c 00 b1 af 18 00 b0 af 10 00 bc af b4 80 99 8f 18 80 92 8f 09 f8 20 03 01 00 11 24}  //weight: 1, accuracy: High
        $x_1_2 = {fb ff 02 24 24 10 02 01 00 0f e3 30 25 10 43 00 01 00 05 24 14 00 a4 ae 10 00 a2 ae 1c 00 a5 ae 00 00 c2 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Getshell_E_2147930753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Getshell.E!MTB"
        threat_id = "2147930753"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Getshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 30 48 89 7d d8 89 f0 66 89 45 d4 ba 00 00 00 00 be 01 00 00 00 bf 02 00 00 00 e8 ?? ?? ?? ?? 89 45 f4 83 7d f4 00 0f ?? ?? ?? ?? ?? 48 8b 45 d8 48 89 c7}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 45 f8 48 83 7d f8 00 0f ?? ?? ?? ?? ?? 48 8d 45 e0 be 10 00 00 00 48 89 c7 e8 ?? ?? ?? ?? 66 c7 45 e0 02 00 48 8b 45 f8 8b 40 14 48 63 d0 48 8b 45 f8 48 8b 40 18 48 8b 00 48 8d 4d e0 48 83 c1 04 48 89 ce 48 89 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

