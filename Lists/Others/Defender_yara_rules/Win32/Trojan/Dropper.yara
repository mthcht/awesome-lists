rule Trojan_Win32_Dropper_AI_2147799481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dropper.AI!MTB"
        threat_id = "2147799481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 3b 45 e0 7e 02 33 c0 8a 94 05 a0 fe ff ff 30 94 0d 9c f2 ff ff 8d 8c 0d 9c f2 ff ff 8b 4d f8 41 3b 4d 08 89 4d f8 7c d7}  //weight: 1, accuracy: High
        $x_1_2 = {0f be 04 11 0f af c1 03 f0 41 3b cf 8d 74 46 05 7e ee}  //weight: 1, accuracy: High
        $x_1_3 = "MeadowSalacity" ascii //weight: 1
        $x_1_4 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dropper_AA_2147806304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dropper.AA!MTB"
        threat_id = "2147806304"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 81 00 01 00 00 0f b6 b9 00 01 00 00 8d 5b 01 0f b6 04 0f 00 81 01 01 00 00 0f b6 b1 01 01 00 00 8a 14 0f 0f b6 04 0e 88 04 0f 88 14 0e 0f b6 81 01 01 00 00 0f b6 91 00 01 00 00 0f b6 04 08 02 04 0a 8b 55 f8 0f b6 c0 0f b6 04 08 32 44 1a ff ff 4d fc 88 43 ff 75 a7}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 37 8b c7 25 3f 00 00 80 79 05 48 83 c8 c0 40 8b 4d fc 47 0f b6 04 08 02 c2 02 d8 0f b6 cb 0f b6 04 31 88 44 37 ff 88 14 31 81 ff 00 01 00 00 7c cd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dropper_CD_2147811173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dropper.CD!MTB"
        threat_id = "2147811173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 c3 f8 d0 c8 f6 d8 d0 c0 fe c9 0f 93 c1 fe c0 32 d8 66 f7 d9 89 14 04}  //weight: 1, accuracy: High
        $x_1_2 = {33 d9 03 f1 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dropper_2147812534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dropper!MTB"
        threat_id = "2147812534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "srcds.pdb" ascii //weight: 2
        $x_2_2 = "bin\\dedicated.dll" ascii //weight: 2
        $x_2_3 = "Local\\Temp\\dca966acd88e0f153d618b8e5840f75be03b3823de7dde6396423edb10cf47a8Srv.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

