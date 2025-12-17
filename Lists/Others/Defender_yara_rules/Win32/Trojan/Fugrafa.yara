rule Trojan_Win32_Fugrafa_RPY_2147888910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fugrafa.RPY!MTB"
        threat_id = "2147888910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fugrafa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 f7 f9 6a 00 89 85 ac fd ff ff 8b c3 99 f7 fe 0f af 8d ac fd ff ff 89 85 b0 fd ff ff 0f af b5 b0 fd ff ff 2b f9 8b c7 99 2b de 2b c2 d1 f8 89 85 a0 fd ff ff 8b c3 99 2b c2 d1 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fugrafa_GN_2147896247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fugrafa.GN!MTB"
        threat_id = "2147896247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fugrafa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8a 04 0e 32 04 1a 43 88 01 8b 45 e8 3b df 72 ed}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fugrafa_KAA_2147900776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fugrafa.KAA!MTB"
        threat_id = "2147900776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fugrafa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QbvThecHeJ" ascii //weight: 1
        $x_1_2 = "d5BlessedYisn.tfspirit4she.dj" ascii //weight: 1
        $x_1_3 = "dry.fitbrought" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fugrafa_SX_2147954518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fugrafa.SX!MTB"
        threat_id = "2147954518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fugrafa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 11 0f b6 85 6b ff ff ff 03 45 a4 03 85 50 ff ff ff 0f b7 4d 88 03 c1 83 c8 ?? 88 85 3f ff ff ff}  //weight: 3, accuracy: Low
        $x_2_2 = {2b f2 0b f1 a1 ?? ?? ?? ?? 66 c1 fe ?? 66 c1 e6 ?? 03 ce 8b f8 c0 e9 ?? c0 e1 ?? 97 8b 5d bc 53 ff d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fugrafa_MK_2147958629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fugrafa.MK!MTB"
        threat_id = "2147958629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fugrafa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {89 85 70 f7 ff ff 33 d2 c6 04 01 ?? 90 0f b7 ?? ?? ?? ?? ?? 8d 52 ?? 66 89 8c 15 7e f9 ff ff 66 85 c9}  //weight: 15, accuracy: Low
        $x_10_2 = {8b 7d b0 03 f9 89 7d d8 8b 17 8b f2 8b 5f cc 8b ca c1 c9 11 c1 ea 0a c1 ce 13 33 f1 8b cb c1 c9 07 33 f2 8b d3 c1 ca 12 33 d1 8b cb c1 e9 03}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fugrafa_NB_2147959636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fugrafa.NB!MTB"
        threat_id = "2147959636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fugrafa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {50 8d 4d f8 e8 df 01 ff ff 8d 4d f8 e8 87 01 00 00 0f b6 d0 85 d2 75 17 c7 45 f0 00 00 00 00 8d 4d f8 e8 51 01 00 00 8b 45 f0 e9 97 00}  //weight: 2, accuracy: High
        $x_1_2 = "WrrySubmerged.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

