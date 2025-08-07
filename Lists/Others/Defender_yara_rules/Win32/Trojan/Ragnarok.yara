rule Trojan_Win32_Ragnarok_GVA_2147948662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ragnarok.GVA!MTB"
        threat_id = "2147948662"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ragnarok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c7 33 d2 f7 75 fc 83 7b 14 07 8d 04 51 8b cb 76 02 8b 0b 8b 55 f8 66 8b 00 66 33 02 66 89 04 79 47 3b 7e 10 72 b6}  //weight: 2, accuracy: High
        $x_1_2 = ".ragnarok" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ragnarok_GVB_2147948663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ragnarok.GVB!MTB"
        threat_id = "2147948663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ragnarok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 f0 55 8d 52 01 66 89 06 8d b5 58 ff ff ff 0f b7 0c 56 8d 34 56 8b c1 66 85 c9 75 e3}  //weight: 2, accuracy: High
        $x_1_2 = ".ragnarok" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

