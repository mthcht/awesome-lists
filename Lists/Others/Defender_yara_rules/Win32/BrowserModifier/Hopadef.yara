rule BrowserModifier_Win32_Hopadef_227966_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Hopadef"
        threat_id = "227966"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Hopadef"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 00 6d 00 6f 00 72 00 68 00 43 00 20 00 65 00 6c 00 00 00 67 00 6f 00 6f 00 47 00 5c 00 6c 00 6c 00 61 00 74 00 73 00 6e 00 69 00 6e 00 55 00 5c 00 6e 00 6f 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 00 78 00 45 00 20 00 74 00 65 00 6e 00 72 00 65 00 74 00 00 00 00 00 6e 00 49 00 5c 00 00 00 25 00 32 00 33 00 34 00 36 00 57 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6f 00 63 00 69 00 2e 00 78 00 6f 00 66 00 65 00 72 00 69 00 66 00 00 00 69 00 65 00 2e 00 69 00 63 00 6f 00}  //weight: 1, accuracy: High
        $x_2_4 = "\\HomePageDefender\\replace_shortcuts\\v2\\installer" ascii //weight: 2
        $x_1_5 = {73 00 74 00 6f 00 70 00 5f 00 61 00 6e 00 64 00 5f 00 72 00 65 00 6d 00 6f 00 76 00 65 00 5f 00 73 00 72 00 76 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "emorhC elgooG\\llatsninU\\noisreVt" wide //weight: 1
        $x_1_7 = "eniLdmChcnuaLsseccuSrellatsnI" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

