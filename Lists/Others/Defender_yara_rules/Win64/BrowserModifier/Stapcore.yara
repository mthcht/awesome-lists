rule BrowserModifier_Win64_Stapcore_409682_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win64/Stapcore"
        threat_id = "409682"
        type = "BrowserModifier"
        platform = "Win64: Windows 64-bit platform"
        family = "Stapcore"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {73 65 61 72 63 68 69 6e 73 74 61 6c 6c 65 72 [0-8] 5c 78 36 34 5c 52 65 6c 65 61 73 65 20 45 6e 63 72 79 70 74 5c 44 65 66 61 75 6c 74 20 53 65 61 72 63 68 20 52 65 64 69 72 65 63 74 6f 72 2e 70 64 62}  //weight: 3, accuracy: Low
        $x_2_2 = ".search-redir.com/p.html?guid=" ascii //weight: 2
        $x_1_3 = "Customize and control Google Chrome" wide //weight: 1
        $x_1_4 = {73 74 61 72 74 6d 69 73 73 69 6e 67 00 00 00 00 73 74 61 72 74 6d 69 73 6d 61 74 63 68 00}  //weight: 1, accuracy: High
        $x_1_5 = "Chrome_WidgetWin_1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

