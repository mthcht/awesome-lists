rule Trojan_Win32_PersistBySchTask_AG_2147957178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PersistBySchTask.AG"
        threat_id = "2147957178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PersistBySchTask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe /create /tn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PersistBySchTask_AF_2147957290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PersistBySchTask.AF"
        threat_id = "2147957290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PersistBySchTask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 74 00 6e 00 [0-128] 20 00 2f 00 73 00 63 00 20 00 6f 00 6e 00 63 00 65 00 20 00 2f 00 66 00 20 00 2f 00 74 00 72 00 20 00 63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 [0-32] 5c 00 61 00 2d 00 [0-22] 2e 00 62 00 61 00 74 00 20 00 2f 00 73 00 74 00 20 00 ?? ?? 3a 00 ?? ?? 3a 00 ?? ?? 20 00 2f 00 72 00 75 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

