rule Trojan_Win32_Chymine_A_2147636566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chymine.A"
        threat_id = "2147636566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chymine"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f1 17 83 c0 02 66 89 0a 8b d0 66 8b 08 66 3b ce 75 ed}  //weight: 1, accuracy: High
        $x_1_2 = {68 42 7c 00 b5 56 e8}  //weight: 1, accuracy: High
        $x_1_3 = "ROOT\\CIMV2" wide //weight: 1
        $x_1_4 = "%s shell32.dll,Control_RunDLLA \"%s\"" wide //weight: 1
        $x_4_5 = {68 70 bf c4 5f 68 ?? ?? ?? ?? c6 45 e0 68 c6 45 e1 74 c6 45 e2 74 c6 45 e3 70 c6 45 e4 3a c6 45 e5 2f c6 45 e6 2f c6 45 e7 32 c6 45 e8 30 c6 45 e9 35 c6 45 ea 2e c6 45 eb 32 c6 45 ec 30 c6 45 ed 39 c6 45 ee 2e c6 45 ef 31 c6 45 f0 37 c6 45 f1 31 c6 45 f2 2e c6 45 f3 31 c6 45 f4 31 c6 45 f5 39 c6 45 f6 2f c6 45 f7 62 c6 45 f8 69 c6 45 f9 6e c6 45 fa 2e c6 45 fb 65 c6 45 fc 78 c6 45 fd 65}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

