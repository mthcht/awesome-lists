rule Trojan_Win32_Minkir_A_2147623620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Minkir.A"
        threat_id = "2147623620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Minkir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "mindw0rker" ascii //weight: 10
        $x_10_2 = "System32\\drivers\\taskmgr.exe" wide //weight: 10
        $x_10_3 = "System32\\drivers\\svchost.exe" wide //weight: 10
        $x_1_4 = {52 00 75 00 6e 00 [0-8] 73 00 76 00 68 00 6f 00 73 00 74}  //weight: 1, accuracy: Low
        $x_1_5 = "%s\\shell\\open\\%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

