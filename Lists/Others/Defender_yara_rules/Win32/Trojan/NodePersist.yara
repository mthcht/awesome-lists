rule Trojan_Win32_NodePersist_Z_2147967779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NodePersist.Z!MTB"
        threat_id = "2147967779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NodePersist"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 65 00 67 00 20 00 61 00 64 00 64 00 [0-16] 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 72 00 75 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = "conhost.exe --headless" wide //weight: 1
        $x_1_3 = {61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 [0-80] 6e 00 6f 00 64 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

