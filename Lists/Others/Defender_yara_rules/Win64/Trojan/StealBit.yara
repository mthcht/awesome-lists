rule Trojan_Win64_StealBit_SC_2147896998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealBit.SC"
        threat_id = "2147896998"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealBit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 8b c1 83 e0 0f 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 83 f9 7c 72 e9 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealBit_SB_2147905499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealBit.SB"
        threat_id = "2147905499"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealBit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "grabber" wide //weight: 1
        $x_1_2 = "\\profiles\\%s\\cookies.sqlite" wide //weight: 1
        $x_1_3 = "\\appdata\\roaming\\mozilla\\firefox" wide //weight: 1
        $x_1_4 = "\\appdata\\local\\google\\chrome\\user data" wide //weight: 1
        $x_1_5 = "\\appdata\\local\\microsoft\\edge\\user data" wide //weight: 1
        $x_1_6 = "_kasssperskdy" wide //weight: 1
        $x_1_7 = "winssyslog" wide //weight: 1
        $x_1_8 = "[conn]" wide //weight: 1
        $x_1_9 = "global\\conn0000000000" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

