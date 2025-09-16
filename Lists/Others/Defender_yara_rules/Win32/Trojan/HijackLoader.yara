rule Trojan_Win32_HijackLoader_AHJ_2147908634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HijackLoader.AHJ!MTB"
        threat_id = "2147908634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HijackLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 56 8b f1 68 d8 c5 00 10 e8 ?? ?? ?? ?? 8a 4c 24 07 33 c0 89 46 1c 88 4e 20 89 46 24 89 46 28 89 46 2c c7 06 c8 84 00 10 8b c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_HijackLoader_SC_2147919111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HijackLoader.SC!MTB"
        threat_id = "2147919111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HijackLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 ba 97 ff ff 80 3e 3d 59 8d 58 01 74 22 6a 01 53 e8 f3 c2 ff ff 59 59 89 07 85 c0 74 3f 56 53 50 e8 c8 cc ff ff 83 c4 0c 85 c0 75 47 83 c7 04 03 f3 80 3e 00 75 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_HijackLoader_GXU_2147952328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HijackLoader.GXU!MTB"
        threat_id = "2147952328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HijackLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 ec 40 89 45 ec 8b 45 ec 3b 45 e4 7d 1c 8b 45 e4 48 2b 45 ec 8b 4d f8 03 4d fc 8a 44 05 b4 88 01 8b 45 fc 40 89 45 fc}  //weight: 10, accuracy: High
        $x_1_2 = "\\Temp\\Web Data" ascii //weight: 1
        $x_1_3 = "\\Temp\\Login Data" ascii //weight: 1
        $x_1_4 = "\\Local\\Temp\\Cookies" ascii //weight: 1
        $x_1_5 = "config\\loginusers.vdf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

