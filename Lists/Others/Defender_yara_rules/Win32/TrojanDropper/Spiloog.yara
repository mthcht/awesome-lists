rule TrojanDropper_Win32_Spiloog_A_2147709997_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Spiloog.A!bit"
        threat_id = "2147709997"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Spiloog"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svchostd.exe" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\AVD_anvir_sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

