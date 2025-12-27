rule Trojan_Win32_CyberGate_ACG_2147919825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CyberGate.ACG!MTB"
        threat_id = "2147919825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CyberGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 33 d2 89 55 e8 89 55 ec 8b d8 33 c0 55 68 5e 6c 00 14 64 ff 30 64 89 20 8d 45 f0 50 e8}  //weight: 2, accuracy: High
        $x_2_2 = {ba 60 68 04 14 b8 01 00 00 80 e8 ?? ?? ?? ?? 68 74 68 04 14 6a 00 6a 00 e8 9f e8 ?? ?? ?? ?? 38 ac 04 14 89 02 b8 d4 5d 04 14 33 c9 33 d2 e8 ?? ?? ?? ?? b8 ac 00 04 14 33 c9 33 d2 e8 ?? ?? ?? ?? b8 ac 82 02 14 33 c9 33 d2}  //weight: 2, accuracy: Low
        $x_1_3 = "SPY_NET_RATMUTEX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CyberGate_MKV_2147953005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CyberGate.MKV!MTB"
        threat_id = "2147953005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CyberGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4d d8 8b 55 dc 8b 52 0c 8b 49 0c 8a 14 1a 8b 7d 94 32 14 39 83 c6 01 88 14 01 8b 45 e4 0f 80 ?? ?? ?? ?? 3b f0 7e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

