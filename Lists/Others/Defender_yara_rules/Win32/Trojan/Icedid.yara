rule Trojan_Win32_Icedid_RB_2147759834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Icedid.RB!MTB"
        threat_id = "2147759834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "slizilinno.top" ascii //weight: 10
        $x_10_2 = "portivitto.top" ascii //weight: 10
        $x_1_3 = "/image/?id=%0.2X%0.8X%0.8X%s" ascii //weight: 1
        $x_1_4 = ".png" ascii //weight: 1
        $x_1_5 = "\\JohnDoe\\Application Data\\JohnDoe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Icedid_VA_2147772989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Icedid.VA!MTB"
        threat_id = "2147772989"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 6a 40 68 ?? ?? ?? ?? 51 6a 00 ff 93 [0-4] 59 5e 89 83 [0-4] 89 c7 f3 a4 8b b3 [0-4] 8d bb [0-4] 29 f7 01 f8 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Icedid_RPL_2147838375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Icedid.RPL!MTB"
        threat_id = "2147838375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 bf e0 07 00 00 29 7d d0 6a 40 68 00 30 00 00 57 53 ff 75 c4 ff 55 84 8b 4d d0 8b 55 cc 03 ca 57 51 50 89 45 c0 ff 55 9c 83 c4 0c 53 6a 40 68 00 30 00 00 ff 75 d0 53 ff 75 c4 ff 55 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Icedid_RPO_2147838377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Icedid.RPO!MTB"
        threat_id = "2147838377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 5a 8b 15 ?? ?? ?? ?? 83 d2 00 a1 ?? ?? ?? ?? 33 f6 2b c8 1b d6 a1 ?? ?? ?? ?? 33 f6 03 c1 13 f2}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 5a 8b c8 33 f6 2b 4d e8 1b 75 ec 0f b7 05 ?? ?? ?? ?? 99 03 c1 13 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

