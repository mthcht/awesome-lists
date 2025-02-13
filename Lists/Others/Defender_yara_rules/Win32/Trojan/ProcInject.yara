rule Trojan_Win32_ProcInject_A_2147594937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcInject.A"
        threat_id = "2147594937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 8b 75 08 89 f7 ac 34 ?? aa e2 fa}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 54 68 72 65 61 64 00 52 65 61 64 50 72 6f 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

