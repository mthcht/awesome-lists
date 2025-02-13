rule Trojan_Win64_Coroxy_MB_2147839829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coroxy.MB!MTB"
        threat_id = "2147839829"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 85 e0 fe ff ff 48 8b bd e0 fe ff ff 48 c7 07 00 01 00 00 48 83 ec 20 48 c7 c1 02 00 00 00 48 8d 57 52 4c 8b c7 ff 15 ?? ?? ?? ?? 48 83 c4 20 48 83 7d 10 00 0f 85}  //weight: 5, accuracy: Low
        $x_3_2 = {8d 6c 56 61 06 2a 15 0d 2a 01 97 e3 02 51 56 fc f3 9d d9 e0 cf ba 8f cf 8d b7 d2 05 c6 6b 49 1a}  //weight: 3, accuracy: High
        $x_2_3 = "rundll" ascii //weight: 2
        $x_2_4 = "socks64.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coroxy_SB_2147851263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coroxy.SB!MTB"
        threat_id = "2147851263"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {14 6d 94 03 50 ?? a2 ?? ?? ?? ?? ?? ?? ?? ?? 3b 82 ?? ?? ?? ?? 12 05 ?? ?? ?? ?? 64 48 e1 ?? ?? 28 7a ?? 66 32 6a}  //weight: 1, accuracy: Low
        $x_1_2 = {1b 3f 33 1e fb 9c 95 09 d2 12 d3 bc}  //weight: 1, accuracy: High
        $x_1_3 = {87 d7 2a e5 d0 69 ?? bc ?? ?? ?? ?? 25 ?? ?? ?? ?? 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coroxy_SPK_2147892395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coroxy.SPK!MTB"
        threat_id = "2147892395"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8d 0d 76 0f 00 00 0f be 04 01 8b 4c 24 28 33 c8 8b c1 48 63 4c 24 20 48 8b 54 24 30 88 04 0a eb a6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coroxy_GZN_2147926382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coroxy.GZN!MTB"
        threat_id = "2147926382"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 2b c8 49 0f af ?? 0f b6 44 0c ?? 49 63 cf 43 32 44 0b ?? 41 88 41 ?? 49 8b c5 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

