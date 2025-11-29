rule Trojan_Win64_BadJoke_KK_2147947322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BadJoke.KK!MTB"
        threat_id = "2147947322"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 8b c1 83 e0 03 42 0f b6 04 30 30 04 0b 48 ff c1 8b 44 24 48 48 3b c8 72}  //weight: 20, accuracy: High
        $x_10_2 = {66 31 18 48 83 c0 02 48 3b c2 75 f4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BadJoke_ARR_2147958505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BadJoke.ARR!MTB"
        threat_id = "2147958505"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {29 ca 8d 0c 92 c1 e1 ?? 29 c8 89 c2 0f 84}  //weight: 15, accuracy: Low
        $x_10_2 = {45 89 f1 41 b8 ?? ?? ?? ?? 48 89 f1 89 6c 24 48 ba}  //weight: 10, accuracy: Low
        $x_5_3 = "C:\\Windows\\System32\\conhost.exe --headless C:\\Windows\\System32\\wlrmdr.exe -s 60000 -f 2 -t \"%s\" -m \"%s\"" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

