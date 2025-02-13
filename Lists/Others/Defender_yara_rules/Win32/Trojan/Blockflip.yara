rule Trojan_Win32_Blockflip_A_2147625278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blockflip.A"
        threat_id = "2147625278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blockflip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Documents and Settings\\Anas\\Desktop\\screen\\Project1.vbp" wide //weight: 1
        $x_1_2 = "\\Windows\\System32\\system process.exe" wide //weight: 1
        $x_1_3 = {5c 00 73 00 77 00 65 00 65 00 74 00 2e 00 65 00 78 00 65 00 00 00 00 00 16 00 00 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00 69 00 64 00 6c 00 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "BlockInput" ascii //weight: 1
        $x_1_5 = {4c 61 62 65 6c 31 00 01 01 0e 00 77 77 77 2e 64 61 68 61 79 61 2e 63 6f 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

