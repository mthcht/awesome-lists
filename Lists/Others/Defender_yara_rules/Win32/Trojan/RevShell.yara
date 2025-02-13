rule Trojan_Win32_RevShell_PS_2147833351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevShell.PS!MTB"
        threat_id = "2147833351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 8d c0 e5 ff ff ba ab 3c 00 00 66 89 95 f8 f7 ff ff b8 ?? ?? ?? ?? 66 89 85 fa f7 ff ff b9 ?? ?? ?? ?? 66 89 8d fc f7 ff ff 33 d2 66 89 95 fe f7 ff ff b8 ?? ?? ?? ?? 66 89 85 84 f4 ff ff b9 ?? ?? ?? ?? 66 89 8d 86 f4 ff ff ba ?? ?? ?? ?? 66 89 95 88 f4 ff ff 33 c0 66 89 85 8a f4 ff ff b9}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 01 00 00 00 c1 e1 02 0f b6 54 0d ac 03 c2 b9 01 00 00 00 c1 e1 02 88 44 0d d4 ba 02 00 00 00 d1 e2}  //weight: 1, accuracy: High
        $x_1_3 = "ReverseShell.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

