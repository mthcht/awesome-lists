rule Trojan_Win32_GoelExaram_B_2147805873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GoelExaram.B"
        threat_id = "2147805873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GoelExaram"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {45 78 61 72 61 6d 65 6c 2d 57 69 6e 64 6f 77 73 2e 64 6c 6c 00 53 74 61 72 74 00 5f 63 67 6f 5f 64 75 6d 6d 79 5f 65 78 70 6f 72 74}  //weight: 3, accuracy: High
        $x_1_2 = "attackevals.mitre-engenuity.org/exaramel-windows/c2" ascii //weight: 1
        $x_1_3 = "attackevals.mitre-engenuity.org/exaramel-windows/discovery" ascii //weight: 1
        $x_1_4 = "attackevals.mitre-engenuity.org/exaramel-windows/execute" ascii //weight: 1
        $x_1_5 = "attackevals.mitre-engenuity.org/exaramel-windows/files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

