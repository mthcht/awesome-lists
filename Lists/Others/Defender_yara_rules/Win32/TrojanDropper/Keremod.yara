rule TrojanDropper_Win32_Keremod_A_2147625464_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Keremod.A"
        threat_id = "2147625464"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Keremod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c6 45 e1 44 c6 45 e2 65 c6 45 e3 73 c6 45 e4 63 c6 45 e5 72 c6 45 e6 69 c6 45 e7 70 c6 45 e8 74 c6 45 e9 6f c6 45 ea 72 c6 45 eb 54 c6 45 ec 61 c6 45 ed 62 c6 45 ee 6c c6 45 ef 65 88 5d f0 ff 15 ?? ?? ?? ?? 3d 04 00 00 c0 75 ?? ff 75 d4 6a 40 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {6a 64 33 d2 59 f7 f1 8b f2 46 c1 e6 04 56 e8 ?? ?? ?? ?? 8b c8 8b c6 89 4c ?? ?? e8 ?? ?? ?? ?? 53 8d 44 ?? ?? 50 56 ff 74 ?? ?? 57 ff 15 ?? ?? ?? ?? ff 74}  //weight: 10, accuracy: Low
        $x_1_3 = "%s\\drivers\\%s.sys" ascii //weight: 1
        $x_1_4 = "sc.exe create %s type= kernel" ascii //weight: 1
        $x_1_5 = "5D42434E-BCA3-4061-9FAC-C3ABEE0B82EC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

