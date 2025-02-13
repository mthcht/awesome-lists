rule Trojan_Win32_BladaInjector_2147744693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BladaInjector!MTB"
        threat_id = "2147744693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BladaInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 ea 00 00 0a 00 16 28 eb 00 00 0a 00 73 01 00 00 06 28 ec 00 00 0a 00 2a}  //weight: 1, accuracy: High
        $x_1_2 = {6f f4 00 00 0a 28 0b 02 00 06 13 0b 11 0b 8e 69 8d 7a 00 00 01 13 0c 16 13 10 2b 19}  //weight: 1, accuracy: High
        $x_1_3 = {28 f6 00 00 0a 6f f7 00 00 0a 16 9a 13 0d 11 0d 1d 8d 0a 00 00 01 25}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BladaInjector_2147744693_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BladaInjector!MTB"
        threat_id = "2147744693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BladaInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 02 00 00 0a a2 25 1a 11 04 a2 28 03 00 00 0a 6f 04 00 00 0a 13 05 28 05 00 00 0a 72 ?? 35 00 70 18 17 8d 01 00 00 01 25 16 11 05 16 11 05 8e 69 28 06 00 00 0a a2 28 07 00 00 0a 74 02 00 00 01 13 06 11 06 6f 08 00 00 0a 16 9a 13 07 73 01 00 00 06 13 08 11 07 19 8d 01 00 00 01 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BladaInjector_2147744693_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BladaInjector!MTB"
        threat_id = "2147744693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BladaInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 22 00 00 0a 1f 0c 8d 10 00 00 01 25 16 06 a2 25 17 07 a2 25 18 08 a2 25}  //weight: 1, accuracy: High
        $x_1_2 = {28 82 00 00 0a 28 ?? ?? 00 06 6f ?? ?? 00 0a 13 ?? 11 ?? 20 ?? ?? 00 00 28 ?? ?? 00 06 6f ?? ?? 00 0a 13 ?? 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {28 52 00 00 06 6f 85 00 00 0a 13 ?? 73 ?? 00 00 06 80 ?? 00 00 04 11 ?? 14 1f ?? 8d ?? 00 00 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

