rule Trojan_Win32_MpUtilAbuse_A_2147763350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpUtilAbuse.A"
        threat_id = "2147763350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpUtilAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mpcmdrun" wide //weight: 1
        $x_1_2 = "downloadfile " wide //weight: 1
        $x_1_3 = "url " wide //weight: 1
        $x_1_4 = "path " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

