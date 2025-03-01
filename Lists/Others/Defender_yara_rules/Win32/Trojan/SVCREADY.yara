rule Trojan_Win32_SVCREADY_DA_2147827259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SVCREADY.DA!MTB"
        threat_id = "2147827259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SVCREADY"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "nAqT.dll" ascii //weight: 1
        $x_1_3 = "AGb6pap64M" ascii //weight: 1
        $x_1_4 = "DGQjdOMUgO" ascii //weight: 1
        $x_1_5 = "SeFllQBaSNu" ascii //weight: 1
        $x_1_6 = "W4Zb9bKml9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

