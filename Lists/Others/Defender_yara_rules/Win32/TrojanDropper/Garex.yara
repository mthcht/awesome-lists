rule TrojanDropper_Win32_Garex_A_2147693308_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Garex.A!dha"
        threat_id = "2147693308"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Garex"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "%SystemRoot%\\System32\\RunDll32.exe \"%ALLUSERSPROFILE%\\Application Data\\DTTEXT.dll\",Update" wide //weight: 4
        $x_1_2 = "%%SystemRoot%%\\System32\\Rundll32.exe %s" wide //weight: 1
        $x_2_3 = "\"%s\",Update {67BDE5D7-C2FC-8898-9096-C255AB791B75}" wide //weight: 2
        $x_2_4 = "%ALLUSERSPROFILE%\\Application Data\\DTTEXT.dll" wide //weight: 2
        $x_2_5 = "-release -tcbp" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

