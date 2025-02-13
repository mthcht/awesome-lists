rule TrojanDropper_Win32_HurlyBurly_A_2147741598_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/HurlyBurly.A!dha"
        threat_id = "2147741598"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "HurlyBurly"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 6b 69 6e 5f 69 6e 73 74 61 6c 6c 20 25 73 00}  //weight: 2, accuracy: High
        $x_2_2 = {ff ff 71 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 6d c6 85 ?? ?? ff ff 63 c6 85 ?? ?? ff ff 6b c6 85 ?? ?? ff ff 6b}  //weight: 2, accuracy: Low
        $x_2_3 = "(C) Microsofts Corporation." wide //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

