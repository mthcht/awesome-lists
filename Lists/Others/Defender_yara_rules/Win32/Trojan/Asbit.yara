rule Trojan_Win32_Asbit_JL_2147837994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Asbit.JL!MTB"
        threat_id = "2147837994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Asbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "106.12.129.126/build?project=loader.core&version=" wide //weight: 1
        $x_1_2 = "loader.dll" wide //weight: 1
        $x_1_3 = "$73fc3849-3bb9-44bf-92c6-85dd7991691c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

