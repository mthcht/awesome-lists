rule Trojan_Win32_NetshHelper_A_2147926862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetshHelper.A"
        threat_id = "2147926862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetshHelper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "netsh.exe" ascii //weight: 1
        $x_1_2 = "add helper" ascii //weight: 1
        $x_1_3 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-143] 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c [0-143] 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

