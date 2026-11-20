rule Trojan_Win64_ShellCodeMarte_BZ_2147981545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeMarte.BZ!MTB"
        threat_id = "2147981545"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeMarte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 15 20 20 00 10 6a 40 68 00 10 00 00 68 00 10 00 00 6a 00 8b 4d e8 51 ff 15 28 20 00 10 89 45 f8 6a 00 68 00 10 00 00 68 00 30 00 10 8b 55 f8 52 8b 45 e8 50 ff 15 2c 20 00 10 8b 4d f8 89 8d 90 fd ff ff 8d 95 d8 fc ff ff 52 8b 45 ec 50 ff 15 24 20 00 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeMarte_FG_2147981605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeMarte.FG!MTB"
        threat_id = "2147981605"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeMarte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 ff 15 20 20 00 10 6a 40 68 00 10 00 00 68 00 00 04 00 6a 00 8b 4d e8 51 ff 15 28 20 00 10 89 45 f8 6a 00 68 00 00 04 00 68 00 40 00 10 8b 55 f8 52 8b 45 e8 50 ff 15 2c 20 00 10 8b 4d f8 89 8d 90 fd ff ff 8d 95 d8 fc ff ff 52 8b 45 ec 50 ff 15 24 20 00 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeMarte_DS_2147982488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeMarte.DS!MTB"
        threat_id = "2147982488"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeMarte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 14 01 83 f2 5a 41 88 14 07 48 83 c0 01 48 83 f8 0b 75 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

