rule Trojan_Win32_CopyRemot_A_2147941480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CopyRemot.A"
        threat_id = "2147941480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CopyRemot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd /c copy /b" wide //weight: 1
        $x_1_2 = {2e 00 63 00 6f 00 6d 00 20 00 2b 00 [0-255] 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CopyRemot_B_2147941481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CopyRemot.B"
        threat_id = "2147941481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CopyRemot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd /c copy /b" wide //weight: 1
        $x_1_2 = {2e 00 74 00 6d 00 70 00 20 00 2b 00 [0-60] 2e 00 74 00 6d 00 70 00 20 00 2b 00 [0-60] 2e 00 74 00 6d 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CopyRemot_C_2147942056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CopyRemot.C"
        threat_id = "2147942056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CopyRemot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 63 00 6f 00 70 00 79 00 20 00 2f 00 62 00 [0-60] 2e 00 [0-32] 2b 00 20 00 [0-60] 2e 00 [0-32] 2b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CopyRemot_C_2147942056_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CopyRemot.C"
        threat_id = "2147942056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CopyRemot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd /c copy /b" wide //weight: 1
        $x_1_2 = {2e 00 76 00 73 00 73 00 20 00 2b 00 [0-60] 2e 00 76 00 73 00 73 00 20 00 2b 00 [0-60] 2e 00 76 00 73 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

