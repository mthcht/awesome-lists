rule BrowserModifier_Win32_PoinBag_165656_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/PoinBag"
        threat_id = "165656"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "PoinBag"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "poinbag.dll" ascii //weight: 1
        $x_1_2 = "check_counter.php?pid=pointbag&mac=" ascii //weight: 1
        $x_1_3 = "Comparison_pointbag.dll" ascii //weight: 1
        $x_1_4 = "pointbag_shop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_PoinBag_165656_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/PoinBag"
        threat_id = "165656"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "PoinBag"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "poinbag" ascii //weight: 1
        $x_1_2 = {43 4f 44 45 25 64 ?? ?? 53 45 41 52 43 48 55 52 4c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6b 65 79 63 6f 64 65 2e 64 61 74}  //weight: 1, accuracy: Low
        $x_1_3 = "domainrefer.dat" ascii //weight: 1
        $x_1_4 = {6a 65 6a 75 2e 6b 72 ?? ?? ?? ?? 2e 67 79 65 6f 6e 67 6e 61 6d 2e 6b 72}  //weight: 1, accuracy: Low
        $x_1_5 = "poinbagup.pdb" ascii //weight: 1
        $x_1_6 = {44 4f 57 4e 55 52 4c ?? 46 49 4c 45 4e 41 4d 45 ?? ?? ?? ?? 53 4f 46 54 57 41 52 45 5c 70 6f 69 6e 62 61 67}  //weight: 1, accuracy: Low
        $x_1_7 = "Exetoday" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

