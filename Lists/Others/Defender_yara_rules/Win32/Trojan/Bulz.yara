rule Trojan_Win32_Bulz_SIB_2147780527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bulz.SIB!MTB"
        threat_id = "2147780527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {60 31 c9 b9 ?? ?? ?? ?? 51 59 83 f9 ?? 75 [0-32] 61 b8 ?? ?? ?? ?? 60 31 c9 b9 ?? ?? ?? ?? 51 59 83 f9 ?? 75 [0-32] 61 50 60 31 c9 b9 ?? ?? ?? ?? 51 59 83 f9 ?? 75 [0-32] 61 68 ?? ?? ?? ?? 60 31 c9 b9 ?? ?? ?? ?? 51 59 83 f9 ?? 75 [0-32] 61 68 ?? ?? ?? ?? 60 31 c9 b9 ?? ?? ?? ?? 51 59 83 f9 ?? 75 [0-32] 61 bb ?? ?? ?? ?? 60 31 c9 b9 ?? ?? ?? ?? 51 59 83 f9 ?? 75 [0-32] 61 ff d3 60 31 c9 b9 ?? ?? ?? ?? 51 59}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bulz_SIBA_2147796674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bulz.SIBA!MTB"
        threat_id = "2147796674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "QQPYHandInputEngine.dll" ascii //weight: 10
        $x_1_2 = {33 c9 33 c0 81 f9 ?? ?? ?? ?? 75 ?? 33 c9 8a 90 ?? ?? ?? ?? 32 d1 80 f2 ?? 41 88 90 02 40 3d ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d 0c 8b 51 ?? 89 55 ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 83 7d 06 ?? 73 ?? 8b 4d ?? c1 e1 ?? 03 4d ?? 8b 55 0c 03 55 02 33 ca 8b 45 0c c1 e8 ?? 03 45 01 33 c8 8b 55 ?? 2b d1 89 55 14 8b 45 14 c1 e0 ?? 03 45 ?? 8b 4d 14 03 4d 02 33 c1 8b 55 14 c1 ea ?? 03 55 ?? 33 c2 8b 4d 0c 2b c8 89 4d 0c 8b 55 02 2b 55 04 89 55 02 8b 45 06 83 c0 ?? 89 45 06 83 7d 06 0a 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Bulz_CE_2147807904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bulz.CE!MTB"
        threat_id = "2147807904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "I am virus! Fuck you" ascii //weight: 1
        $x_1_2 = "The software you just executed is considered malware" ascii //weight: 1
        $x_1_3 = "This Trojan will harm your computer" ascii //weight: 1
        $x_1_4 = "You are infected LMAO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bulz_CB_2147815678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bulz.CB!MTB"
        threat_id = "2147815678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "execute this malware?" ascii //weight: 1
        $x_1_2 = "You are fucked by a.exe" ascii //weight: 1
        $x_1_3 = "Thanks to Nathantor for helping me" ascii //weight: 1
        $x_1_4 = "execute?" ascii //weight: 1
        $x_1_5 = "last warning" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bulz_GZF_2147902853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bulz.GZF!MTB"
        threat_id = "2147902853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 24 33 d2 89 54 24 0c 50 89 54 24 14 66 c7 44 24 10 02 00 89 54 24 18 89 54 24 1c e8 ?? ?? ?? ?? 8b 74 24 20 66 89 44 24 0e 85 f6 ?? ?? 56 e8 ?? ?? ?? ?? 89 44 24 10 ?? ?? 56 e8}  //weight: 10, accuracy: Low
        $x_1_2 = "zaccl.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bulz_GNM_2147919605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bulz.GNM!MTB"
        threat_id = "2147919605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f3 c0 00 fb fd 23 54 ff 2a 46 34 ff fc f6 c0 fb 32 04 00 58 ff 54 ff f3 53 21 eb f3 e3 12}  //weight: 10, accuracy: High
        $x_1_2 = "e8it.net/tuiguang/qudao" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

