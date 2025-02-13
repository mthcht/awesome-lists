rule Trojan_Win32_BlockMpTamperProtectedContent_A_2147760389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlockMpTamperProtectedContent.A"
        threat_id = "2147760389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlockMpTamperProtectedContent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wsreset.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlockMpTamperProtectedContent_B_2147762141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlockMpTamperProtectedContent.B"
        threat_id = "2147762141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlockMpTamperProtectedContent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 6b 00 6c 00 69 00 6e 00 6b 00 [0-128] 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 3a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

