rule Trojan_Win32_MreAgent_B_2147920758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MreAgent.B"
        threat_id = "2147920758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MreAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic" wide //weight: 1
        $x_1_2 = "process call create" wide //weight: 1
        $x_1_3 = "ie4uinit.exe -basesettings" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MreAgent_F_2147920759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MreAgent.F"
        threat_id = "2147920759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MreAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 72 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 6d 00 73 00 78 00 73 00 6c 00 2e 00 65 00 78 00 65 00 [0-255] 2e 00 74 00 78 00 74 00 20 00 [0-255] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $n_100_2 = " -o " wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

