rule Trojan_Win32_GameThief_SIB_2147794371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GameThief.SIB!MTB"
        threat_id = "2147794371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GameThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f1 33 d2 [0-16] 8a 0f [0-16] 8a 06 46 47 80 7d 08 ?? 88 4d ?? 0f 84 ?? ?? ?? ?? 8a ca c0 cf ?? bb ?? ?? ?? ?? d3 c3 8a 4d 05 [0-16] 02 da 32 c3 42 [0-16] 84 c0 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GameThief_GMQ_2147892635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GameThief.GMQ!MTB"
        threat_id = "2147892635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GameThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {45 64 69 74 41 ?? 73 77 65 72 32 48 03 00 00 01 00 08 45 64 69 74 50 ?? 65 72 4c 03}  //weight: 10, accuracy: Low
        $x_1_2 = "OLGame.itm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

