rule TrojanSpy_Win32_Migeon_A_2147697736_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Migeon.A!dha"
        threat_id = "2147697736"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Migeon"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 c2 fe 09 00 00 b9 ff 01 00 00}  //weight: 5, accuracy: High
        $x_5_2 = {b9 00 16 00 00 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 02 02 00 00 b9 ff 01 00 00}  //weight: 5, accuracy: Low
        $x_1_3 = "rundll32.exe %s,Player" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

