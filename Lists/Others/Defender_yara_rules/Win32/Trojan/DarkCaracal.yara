rule Trojan_Win32_DarkCaracal_NEAA_2147841216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkCaracal.NEAA!MTB"
        threat_id = "2147841216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkCaracal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "msinfo32.exe" ascii //weight: 5
        $x_2_2 = "Fdfadadasdsa7d8sad8a" ascii //weight: 2
        $x_2_3 = "JHDSJDH7e7w7ew7e6ew7" ascii //weight: 2
        $x_2_4 = "VDkdjakdjakdsadadasda" ascii //weight: 2
        $x_2_5 = "CEDREKASMPS" ascii //weight: 2
        $x_2_6 = "Internet Explorer\\iexplore.exe" ascii //weight: 2
        $x_1_7 = "poOwnerFormCenter" ascii //weight: 1
        $x_1_8 = "TDCP_blockcipher64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

