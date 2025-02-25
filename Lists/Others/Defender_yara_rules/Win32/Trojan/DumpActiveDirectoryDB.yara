rule Trojan_Win32_DumpActiveDirectoryDB_ZPA_2147934402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DumpActiveDirectoryDB.ZPA"
        threat_id = "2147934402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpActiveDirectoryDB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ntdsutil" wide //weight: 1
        $x_1_2 = "ac i ntds" wide //weight: 1
        $x_1_3 = "\"ifm\"" wide //weight: 1
        $x_1_4 = "create full" wide //weight: 1
        $x_1_5 = " q q" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

