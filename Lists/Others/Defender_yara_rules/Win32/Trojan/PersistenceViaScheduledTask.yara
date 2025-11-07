rule Trojan_Win32_PersistenceViaScheduledTask_AB_2147931918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PersistenceViaScheduledTask.AB"
        threat_id = "2147931918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PersistenceViaScheduledTask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 74 00 6e 00 [0-5] 61 00 74 00 74 00 61 00 63 00 6b 00 69 00 71 00 20 00 74 00 61 00 73 00 6b 00}  //weight: 3, accuracy: Low
        $x_3_2 = {2f 00 74 00 72 00 [0-5] 63 00 6d 00 64 00 20 00 2f 00 63 00 [0-64] 2e 00 62 00 61 00 74 00 [0-64] 2f 00 72 00 75 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PersistenceViaScheduledTask_AC_2147933666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PersistenceViaScheduledTask.AC"
        threat_id = "2147933666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PersistenceViaScheduledTask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 74 00 6e 00 [0-128] 20 00 2f 00 73 00 63 00 20 00 6f 00 6e 00 63 00 65 00 20 00 2f 00 66 00 20 00 2f 00 74 00 72 00 20 00 63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 61 00 2d 00 [0-22] 2e 00 62 00 61 00 74 00 20 00 2f 00 73 00 74 00 20 00 ?? ?? ?? ?? 3a 00 ?? ?? ?? ?? 3a 00 ?? ?? ?? ?? 20 00 2f 00 72 00 75 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PersistenceViaScheduledTask_AE_2147949599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PersistenceViaScheduledTask.AE"
        threat_id = "2147949599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PersistenceViaScheduledTask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 74 00 6e 00 [0-128] 20 00 2f 00 73 00 63 00 20 00 6f 00 6e 00 63 00 65 00 20 00 2f 00 66 00 20 00 2f 00 74 00 72 00 20 00 63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 [0-32] 5c 00 61 00 2d 00 [0-22] 2e 00 62 00 61 00 74 00 20 00 2f 00 73 00 74 00 20 00 ?? ?? ?? ?? 3a 00 ?? ?? ?? ?? 3a 00 ?? ?? ?? ?? 20 00 2f 00 72 00 75 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PersistenceViaScheduledTask_AF_2147956999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PersistenceViaScheduledTask.AF"
        threat_id = "2147956999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PersistenceViaScheduledTask"
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

rule Trojan_Win32_PersistenceViaScheduledTask_AG_2147957000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PersistenceViaScheduledTask.AG"
        threat_id = "2147957000"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PersistenceViaScheduledTask"
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

