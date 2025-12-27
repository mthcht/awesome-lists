rule Trojan_Win32_DllExecuteAbuse_A_2147957001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllExecuteAbuse.A"
        threat_id = "2147957001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllExecuteAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 [0-240] 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 5f 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 20 00 77 00 72 00 69 00 74 00 65 00 74 00 6f 00 74 00 65 00 6d 00 70 00 66 00 69 00 6c 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllExecuteAbuse_B_2147957002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllExecuteAbuse.B"
        threat_id = "2147957002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllExecuteAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32_dll.dll" wide //weight: 1
        $x_1_2 = "writetotempfile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

