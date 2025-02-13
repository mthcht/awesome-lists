rule Trojan_Win32_NetStream_DSK_2147744126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetStream.DSK!MTB"
        threat_id = "2147744126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetStream"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d6 8b ca b8 89 dc 00 00 03 c1 2d 89 dc 00 00 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetStream_DSK_2147744126_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetStream.DSK!MTB"
        threat_id = "2147744126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetStream"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 75 f8 33 f2 b8 26 09 00 00 b8 26 09 00 00 b8 26 09 00 00 b8 26 09 00 00 b8 26 09 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {b8 26 09 00 00 8b d6 8b ca b8 89 dc 00 00 03 c1 2d 89 dc 00 00 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetStream_PDS_2147745357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetStream.PDS!MTB"
        threat_id = "2147745357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetStream"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d7 8b ca b8 05 00 00 00 03 c1 83 e8 05 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 5c 05 f8 30 9c 3d ?? ?? ?? ?? 8b c6 83 e0 03 83 c6 06 8a 54 05 f8 30 94 3d ?? ?? ?? ?? 8d 41 ff 83 e0 03 83 e1 03 8a 44 05 f8 30 84 3d ?? ?? ?? ?? 8a 44 0d f8 30 84 3d ?? ?? ?? ?? 30 9c 3d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

