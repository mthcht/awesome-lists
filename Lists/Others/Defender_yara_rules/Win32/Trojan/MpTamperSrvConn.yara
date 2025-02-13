rule Trojan_Win32_MpTamperSrvConn_D_2147929758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperSrvConn.D"
        threat_id = "2147929758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperSrvConn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "add-dnsclientnrptrule" wide //weight: 1
        $x_1_2 = {2d 00 6e 00 61 00 6d 00 65 00 73 00 70 00 61 00 63 00 65 00 [0-48] 65 00 6e 00 64 00 70 00 6f 00 69 00 6e 00 74 00 2e 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2e 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2d 00 6e 00 61 00 6d 00 65 00 73 00 65 00 72 00 76 00 65 00 72 00 73 00 [0-48] 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MpTamperSrvConn_A_2147930301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperSrvConn.A"
        threat_id = "2147930301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperSrvConn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 6f 00 75 00 74 00 65 00 [0-48] 61 00 64 00 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = "0.0.0.0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

