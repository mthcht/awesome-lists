rule BrowserModifier_Win32_FreeScratchAndWin_5475_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/FreeScratchAndWin"
        threat_id = "5475"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "FreeScratchAndWin"
        severity = "12"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "FSC\\FSCClient" ascii //weight: 3
        $x_3_2 = "%s\\fsc.ini" ascii //weight: 3
        $x_2_3 = {75 72 6c 5f 74 65 72 6d 73 [0-6] 75 72 6c 5f 66 69 6c 65 73 [0-6] 75 72 6c 5f 61 64 73 65 72 76 [0-6] 75 72 6c 5f 72 6f 6f 74 [0-6] 66 69 6c 65 6c 69 73 74}  //weight: 2, accuracy: Low
        $x_1_4 = "Free Scratch Cards!" ascii //weight: 1
        $x_1_5 = "free-scratch-cards.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

