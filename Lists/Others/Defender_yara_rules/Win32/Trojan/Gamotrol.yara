rule Trojan_Win32_Gamotrol_A_2147711608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamotrol.A!bit"
        threat_id = "2147711608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamotrol"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 03 74 01 e8 83 c0 00 55}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 f4 4f c6 45 f5 70 88 5d f6 c6 45 f7 6e 66 89 45 e5 88 45 e7 c6 45 d8 53 c6 45 d9 68 88 5d da c6 45 db 6c c6 45 dc 6c c6 45 dd 45 c6 45 de 78 88 5d df c6 45 e0 63 c6 45 e1 75 c6 45 e2 74 88 5d e3 c6 45 e4 41}  //weight: 1, accuracy: High
        $x_3_3 = {73 75 78 63 66 71 00 61 62 00 00 00 5c 6e 65 73 74 72 61 73 2e 64 6c 6c}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

