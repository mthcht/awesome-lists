rule BrowserModifier_Win32_Kerlofost_139094_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Kerlofost"
        threat_id = "139094"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Kerlofost"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Browser Helper Objects" ascii //weight: 10
        $x_10_2 = {2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 10, accuracy: High
        $x_2_3 = "reklosoft.ru" ascii //weight: 2
        $x_2_4 = "reklosoft_adw." ascii //weight: 2
        $x_1_5 = "FFFFE708-B832-42F1-BAFF-247753B5E452" ascii //weight: 1
        $x_1_6 = "71E59D37-D7FC-4ED6-BC1D-D13BE02FE6C5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

