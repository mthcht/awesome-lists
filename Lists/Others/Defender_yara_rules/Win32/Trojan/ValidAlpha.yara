rule Trojan_Win32_ValidAlpha_A_2147916850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValidAlpha.A!dha"
        threat_id = "2147916850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValidAlpha"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {66 c7 00 ab cd c6 40 02 ef ?? 03 00 00 00 48 89 c1 ?? 03 00 00 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValidAlpha_B_2147916851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValidAlpha.B!dha"
        threat_id = "2147916851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValidAlpha"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "400"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "main.ScreenMonitThread" ascii //weight: 100
        $x_100_2 = "main.CmdShell" ascii //weight: 100
        $x_100_3 = "main.GetAllFoldersAndFiles" ascii //weight: 100
        $x_100_4 = "main.SelfDelete" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

