rule TrojanSpy_Win32_Bradesco_A_2147724627_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bradesco.A!bit"
        threat_id = "2147724627"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bradesco"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yourlifeinthesun.com/AplicativoBradesco.exe" wide //weight: 1
        $x_1_2 = "\\svl\\DevWarningPatch.bat" wide //weight: 1
        $x_1_3 = "\\GbPlugin\\cef.gpc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

