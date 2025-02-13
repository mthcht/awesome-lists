rule Trojan_Win32_Blaruv_A_2147682057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blaruv.A"
        threat_id = "2147682057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blaruv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%appdata%\\nightupdate\\" ascii //weight: 1
        $x_1_2 = "/gate.php?cmd=urls" ascii //weight: 1
        $x_1_3 = "/gate.php?reg=" ascii //weight: 1
        $x_1_4 = "blackrev" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

