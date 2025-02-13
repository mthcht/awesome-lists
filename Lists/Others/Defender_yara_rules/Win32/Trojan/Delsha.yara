rule Trojan_Win32_Delsha_C_13631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delsha.C"
        threat_id = "13631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delsha"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net share \"ipc$\" /delete /y" ascii //weight: 1
        $x_1_2 = "net share \"admin$\" /delete /y" ascii //weight: 1
        $x_1_3 = {50 41 54 48 00 00 00 00 2e 63 6f 6d 00 00 00 00 2e 65 78 65 00 00 00 00 2e 62 61 74}  //weight: 1, accuracy: High
        $x_2_4 = {44 6f 63 73 22 00 00 00 22 4d 79 20 44 6f 63 75 6d 65 6e 74 73 22 00 00 22 70 72 69 6e 74 24 22}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

