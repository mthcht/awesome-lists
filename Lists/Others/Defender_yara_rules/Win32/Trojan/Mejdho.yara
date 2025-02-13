rule Trojan_Win32_Mejdho_A_2147602086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mejdho.A"
        threat_id = "2147602086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mejdho"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 02 6a 00 6a c4 ff b5 ac fe ff ff ff 15 ?? ?? ?? 00 83 65 ec 00 6a 00 8d 45 ec 50 6a 3c 8d 85 b0 fe ff ff 50 ff b5 ac fe ff ff ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {74 35 68 44 10 00 00 ff 75 10 e8 ?? ?? ?? 00 59 59 6a 00 8d 45 f8 50 68 44 10 00 00 ff 75 10 ff 75 d4 ff 15 ?? ?? ?? 00 68 44 10 00 00 ff 75 10 e8 ?? ?? ?? 00 59 59}  //weight: 10, accuracy: Low
        $x_1_3 = "\\SVCHOST.EXE" ascii //weight: 1
        $x_1_4 = "myguid" ascii //weight: 1
        $x_1_5 = "myparentthreadid" ascii //weight: 1
        $x_1_6 = "Global\\ps" ascii //weight: 1
        $x_1_7 = {2e 65 78 65 00 00 00 00 2e 73 63 6f 00 00 00 00 2e 70 72 6f 00 00 00 00 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

