rule Trojan_Win64_OysterLoader_YAB_2147912418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OysterLoader.YAB!MTB"
        threat_id = "2147912418"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OysterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 2b c8 48 03 cb 8a 44 0c 20 43 32 04 13 41 88 02 4d 03 d4}  //weight: 1, accuracy: High
        $x_1_2 = {49 63 c9 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 45 03 cc 48 f7 e1 48 c1 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_OysterLoader_GZZ_2147945207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OysterLoader.GZZ!MTB"
        threat_id = "2147945207"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OysterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 83 ec 28 ba ?? ?? ?? ?? 31 c9 41 b8 00 30 00 00 41 b9 40 00 00 00 ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {41 ff d6 48 89 c7 48 89 f1 ba 02 00 00 00 41 ff d7}  //weight: 5, accuracy: High
        $x_5_3 = {41 ff d7 48 89 c7 48 89 f1 ba 02 00 00 00 ff 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

