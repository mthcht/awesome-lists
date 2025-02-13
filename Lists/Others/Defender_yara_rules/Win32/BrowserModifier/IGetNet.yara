rule BrowserModifier_Win32_IGetNet_6941_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/IGetNet"
        threat_id = "6941"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "IGetNet"
        severity = "11"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 68 65 6c 6c 33 32 32 2e 65 78 65 [0-4] 53 79 73 74 65 6d}  //weight: 1, accuracy: Low
        $x_1_2 = {62 68 6f 2e 64 6c 6c 00 62 68 6f 2e 64 6c 5f}  //weight: 1, accuracy: High
        $x_1_3 = "Overwriting HOSTS file '%s'." ascii //weight: 1
        $x_1_4 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 [0-8] 69 00 47 00 65 00 74 00 4e 00 65 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

