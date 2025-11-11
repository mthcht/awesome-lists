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

