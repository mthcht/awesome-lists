rule Trojan_Win32_Tnaket_A_2147917261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnaket.A!MTB"
        threat_id = "2147917261"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnaket"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 53 48 83 ec 20 45 33 c0 48 c7 41 18 07 00 00 00 48 8b d9 4c 89 41 10 66 44 89 01 66 44 39 02 74 11 48 83 c8 ff}  //weight: 1, accuracy: High
        $x_1_2 = "ReflectiveLoader" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

