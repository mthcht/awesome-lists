rule Trojan_Win32_PowhidSubExec_B_2147941383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowhidSubExec.B"
        threat_id = "2147941383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowhidSubExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = {68 00 69 00 64 00 64 00 65 00 6e 00 [0-60] 24 00}  //weight: 1, accuracy: Low
        $x_1_3 = "appdata" wide //weight: 1
        $x_1_4 = {2e 00 73 00 75 00 62 00 73 00 74 00 72 00 69 00 6e 00 67 00 [0-60] 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

