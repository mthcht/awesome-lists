rule Trojan_Win32_PriteAddUser_B_2147784147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PriteAddUser.B"
        threat_id = "2147784147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PriteAddUser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/add" wide //weight: 1
        $x_1_2 = "net user " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

