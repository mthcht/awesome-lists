rule Trojan_Win32_Dorifel_A_2147672233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dorifel.A"
        threat_id = "2147672233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorifel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 76 63 68 6f 73 74 2e 65 78 65 00 31 31 38 2e 31 30 33 2e 31 32 33 2e 32 32 37}  //weight: 1, accuracy: High
        $x_1_2 = {45 61 70 48 6f 73 74 00 61 61 61 61}  //weight: 1, accuracy: High
        $x_1_3 = {62 62 62 62 2e 64 6c 6c 00 00 4d 65 73 73 65 6e 67 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dorifel_EC_2147850304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dorifel.EC!MTB"
        threat_id = "2147850304"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorifel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Adobe3D\\adobloc.exe" ascii //weight: 1
        $x_1_2 = "\\LabZ64\\xoptisys.exe" ascii //weight: 1
        $x_1_3 = "KEYKEY0" ascii //weight: 1
        $x_1_4 = "netstat.txt" ascii //weight: 1
        $x_1_5 = "grubb.list" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dorifel_EALB_2147939538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dorifel.EALB!MTB"
        threat_id = "2147939538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorifel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c7 44 24 10 00 00 00 00 8d 55 e4 89 54 24 0c d1 e0 89 44 24 08 89 74 24 04 89 1c 24}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

