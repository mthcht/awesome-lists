rule Trojan_Win32_starter_KA_2147773790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/starter.KA!MTB"
        threat_id = "2147773790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 44 24 10 8b 08 8a 54 29 03 8a c2 8a da 80 e2 f0 c0 e0 06 0a 44 29 02 80 e3 fc c0 e2 02 0a 14 29 c0 e3 04 0a 5c 29 01 83 c5 04 88 14 3e 88 5c 3e 01 88 44 3e 02 83 c6 03 8b 44 24 14 3b 28 72 bf}  //weight: 2, accuracy: High
        $x_2_2 = {8b 44 24 1c 03 44 24 14 33 c8 29 4c 24 10 b9 f7 ff ff ff 8b 44 24 28 2b c8 03 4c 24 1c 89 4c 24 1c ff 44 24 18 83 7c 24 18 20 72 80 8b 74 24 20 8b 5c 24 2c 8b 44 24 10 8b 6c 24 34 89 04 f3 8b 44 24 14 89 44 f3 04 46 89 74 24 20 3b 74 24 30 0f 82 11 ff ff ff}  //weight: 2, accuracy: High
        $x_1_3 = "nutavecehenubepuhuguwujejixafu.jpg" ascii //weight: 1
        $x_1_4 = "pacelunuyifunogacebora.txt" ascii //weight: 1
        $x_1_5 = "zumedelocifucavoxilituvabu.txt" ascii //weight: 1
        $x_1_6 = "hudejitafepijiwagekuwi.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

