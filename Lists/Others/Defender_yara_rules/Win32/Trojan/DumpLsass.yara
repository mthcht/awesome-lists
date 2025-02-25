rule Trojan_Win32_DumpLsass_ZPA_2147934392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DumpLsass.ZPA"
        threat_id = "2147934392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-accepteula -ma lsass.exe" wide //weight: 1
        $x_1_2 = "-accepteula -mm lsass.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_DumpLsass_ZPB_2147934393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DumpLsass.ZPB"
        threat_id = "2147934393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rundll32" wide //weight: 1
        $x_1_2 = {64 00 75 00 6d 00 70 00 65 00 72 00 74 00 2e 00 64 00 6c 00 6c 00 2c 00 [0-4] 64 00 75 00 6d 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DumpLsass_ZPC_2147934394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DumpLsass.ZPC"
        threat_id = "2147934394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dumpert.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DumpLsass_ZPD_2147934395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DumpLsass.ZPD"
        threat_id = "2147934395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nanodump" wide //weight: 1
        $x_1_2 = " -w " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DumpLsass_ZPE_2147934397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DumpLsass.ZPE"
        threat_id = "2147934397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pypykatz" wide //weight: 1
        $x_1_2 = "live lsa" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

