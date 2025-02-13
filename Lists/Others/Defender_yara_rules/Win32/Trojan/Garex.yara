rule Trojan_Win32_Garex_2147693314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Garex!dha"
        threat_id = "2147693314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Garex"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppInitDLLs" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows Update Reporting" ascii //weight: 1
        $x_1_3 = "PythonThreadStart" ascii //weight: 1
        $x_1_4 = "PythonThreadStop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

