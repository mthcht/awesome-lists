rule Trojan_Win32_ZenarMiner_PA_2147781870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZenarMiner.PA!MTB"
        threat_id = "2147781870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZenarMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/K taskkill /IM" ascii //weight: 1
        $x_1_2 = "mirkosirko@pigmo" wide //weight: 1
        $x_1_3 = "iplogger.org" wide //weight: 1
        $x_1_4 = "\\Zenar.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

