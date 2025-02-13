rule Trojan_Win32_Iceid_SC_2147735142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iceid.SC!MTB"
        threat_id = "2147735142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iceid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d2 4a 23 13 83 eb ?? f7 da 83 ea ?? 83 c2 ?? 42 29 ca 8d 0a 6a 00 8f 07 01 17 83 c7 ?? 83 e8 ?? 3d ?? ?? 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 8d 05 ?? ?? ?? ?? ff d0 59 83 f8 00 0f 50 00 8d 0d ?? ?? ?? ?? 51 6a ?? 83 04 24 ?? 68 ?? ?? 00 00 83 04 24 ?? 68 ?? ?? 00 00 83 04 24 ?? 6a 00 8d 05 ?? ?? ?? ?? ff d0 59 83 f8 00 0f 50 00}  //weight: 1, accuracy: Low
        $x_1_3 = {89 ec 5d f1 ff 35 ?? ?? ?? ?? c3 ff 35 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Iceid_SB_2147735535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iceid.SB!MTB"
        threat_id = "2147735535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iceid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 8d 05 ?? ?? ?? ?? ff d0 59 83 f8 00 0f 50 00 8d 0d ?? ?? ?? ?? 51 6a ?? 83 04 24 ?? 68 ?? ?? 00 00 83 04 24 ?? 68 ?? ?? 00 00 83 04 24 ?? 6a 00 8d 05 ?? ?? ?? ?? ff d0 59 83 f8 00 0f 50 00}  //weight: 1, accuracy: Low
        $x_1_2 = {89 ec 5d f1 ff 35 ?? ?? ?? ?? c3 ff 35 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Iceid_SX_2147739861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iceid.SX!MTB"
        threat_id = "2147739861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iceid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 50 8b c3 5a 8b ca 33 d2 f7 f1 8a 04 16 30 04 1f 43 3b 5d 10 75}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 04 a8 03 75 ?? 8b 10 83 c0 04 8b ca 81 ea 01 01 01 01 81 e2 80 80 80 80 74 eb f7 d1 23 d1 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Iceid_BB_2147740449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iceid.BB!MTB"
        threat_id = "2147740449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iceid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 43 83 04 24 fd 68 03 10 00 00 83 04 24 fd 68 d3 08 00 00 83 04 24 fd 6a 00}  //weight: 1, accuracy: High
        $x_1_2 = "AJHRKIT.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Iceid_A_2147740710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iceid.A!MTB"
        threat_id = "2147740710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iceid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 fc 33 d2 f7 75 14 8b 45 08 0f be 0c 10 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Iceid_AK_2147780416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iceid.AK!MTB"
        threat_id = "2147780416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iceid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d1 ed 6a 00 5f 74 ?? 8d 58 ?? 0f b7 13 89 54 24 ?? 66 c1 6c 24 1c ?? 0f b7 d2 c7 44 24 ?? 00 10 00 00 66 3b 54 24 ?? 72 ?? 81 e2 ff 0f 00 00 03 51 04 03 10 66 83 7c 24 ?? 03 75 ?? 01 32 47 83 c3 02 3b fd 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Iceid_AK_2147780416_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iceid.AK!MTB"
        threat_id = "2147780416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iceid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af f7 44 31 ce 83 ce fe 6b c0 37 89 c7 81 c7 c3 f6 ff ff 48 63 ff 48 69 ff 09 04 02 81 48 c1 ef 20 01 c7 81 c7 c3 f6 ff ff 89 fb c1 eb 1f c1 ff 06 01 df 89 fb c1 e3 07 29 df 8d [0-129] c3 c3 f6 ff ff 01 f8 05 42 f7 ff ff 48 98 48 69 c0 09 04 02 81 48 c1 e8 20 01 d8 83 c0 7f 89 c7 c1 ef 1f c1 f8 06 01 f8 89 c7 c1 e7 07 29 f8 44 39 ce 0f ?? ?? ?? ?? 40 0f 94 c6 41 be 98 7e 19 44 45 0f 44 f7 41 83 fa 0a 0f ?? ?? ?? ?? 0f 9c c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Iceid_PC_2147838858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iceid.PC!MTB"
        threat_id = "2147838858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iceid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hNI_OnLoad" ascii //weight: 1
        $x_1_2 = "init" ascii //weight: 1
        $x_1_3 = "hava_com_sun_imageio_plugins_jpeg_JPEGImageReader_" ascii //weight: 1
        $x_1_4 = "hava_com_sun_imageio_plugins_jpeg_JPEGImageWriter_" ascii //weight: 1
        $x_1_5 = "javajpeg.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

