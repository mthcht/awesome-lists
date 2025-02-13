rule BrowserModifier_Win32_Plorexie_225962_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Plorexie"
        threat_id = "225962"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Plorexie"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 00 45 00 58 00 50 00 4c 00 4f 00 52 00 45 00 00 00 49 00 6e 00 74 00 72 00 65 00 6e 00 65 00 74 00 2e 00 20 00 45 00 78 00 70 00 6c 00 65 00 72 00 6f 00 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 43 00 68 00 72 00 6f 00 6d 00 6f 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: High
        $x_1_3 = {4d 00 6f 00 7a 00 6c 00 69 00 6c 00 61 00 20 00 46 00 72 00 69 00 65 00 66 00 6f 00 78 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 49 00 6e 00 70 00 72 00 6f 00 63 00 53 00 65 00 72 00 76 00 65 00 72 00 33 00 32 00 ?? ?? ?? ?? ?? ?? 5c 00 74 00 6f 00 6f 00 6c 00 73 00 5c 00 62 00 64 00 6d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_5 = "%31%32%33%2E%61%31%30%31%2E%63%63/u.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

