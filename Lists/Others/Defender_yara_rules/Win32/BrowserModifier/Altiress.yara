rule BrowserModifier_Win32_Altiress_235002_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Altiress"
        threat_id = "235002"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Altiress"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&event=ex_update_start" wide //weight: 1
        $x_1_2 = "&event=ex_install_start" wide //weight: 1
        $x_1_3 = "Express Software" wide //weight: 1
        $x_1_4 = {4d 00 61 00 69 00 6e 00 00 00 53 00 74 00 61 00 72 00 74 00 20 00 50 00 61 00 67 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

