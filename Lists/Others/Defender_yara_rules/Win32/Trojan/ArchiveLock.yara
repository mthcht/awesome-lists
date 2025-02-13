rule Trojan_Win32_ArchiveLock_A_2147684573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArchiveLock.A"
        threat_id = "2147684573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArchiveLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 72 65 67 20 64 65 6c 65 74 65 20 48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 61 20 2f 66 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 52 45 47 20 41 44 44 20 22 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 57 69 6e 64 6f 77 73 20 45 72 72 6f 72 20 52 65 70 6f 72 74 69 6e 67 22 20 2f 76 20 22 44 69 73 61 62 6c 65 41 72 63 68 69 76 65 22 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 31 20 2f 66 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 73 76 63 66 6e 6d 61 69 6e 73 74 76 65 73 74 76 73 5c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ArchiveLock_B_2147684574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArchiveLock.B"
        threat_id = "2147684574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArchiveLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 6c 73 61 73 73 38 36 76 6c 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "system32\\sdelete.dll" ascii //weight: 1
        $x_1_3 = {68 a0 bb 0d 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 00 00 00 00 e8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

