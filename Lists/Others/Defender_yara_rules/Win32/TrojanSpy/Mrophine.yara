rule TrojanSpy_Win32_Mrophine_A_2147709685_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Mrophine.A!bit"
        threat_id = "2147709685"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Mrophine"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[CLIPBOARD END]" wide //weight: 1
        $x_1_2 = {53 00 74 00 61 00 74 00 75 00 73 00 3a 00 20 00 6d 00 6f 00 72 00 70 00 68 00 69 00 6e 00 45 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

