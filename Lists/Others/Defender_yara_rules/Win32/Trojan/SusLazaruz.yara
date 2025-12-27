rule Trojan_Win32_SusLazaruz_A_2147955563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusLazaruz.A"
        threat_id = "2147955563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusLazaruz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetLogicalDriveStringsW-GetDriveType.exe" ascii //weight: 1
        $x_1_2 = "%TMP%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

