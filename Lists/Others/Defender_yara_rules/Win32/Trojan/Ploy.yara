rule Trojan_Win32_Ploy_B_2147642828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ploy.B"
        threat_id = "2147642828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ploy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Keymycy" ascii //weight: 1
        $x_1_2 = "UMI.dll" ascii //weight: 1
        $x_1_3 = "http://keymycyvip.uueasy.com/" ascii //weight: 1
        $x_1_4 = "\\shell\\open\\command" ascii //weight: 1
        $x_1_5 = "\\UMI.INI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

