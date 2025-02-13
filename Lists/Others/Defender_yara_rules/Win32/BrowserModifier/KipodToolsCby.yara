rule BrowserModifier_Win32_KipodToolsCby_207199_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/KipodToolsCby"
        threat_id = "207199"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "KipodToolsCby"
        severity = "56"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KipodTools::IETools::" ascii //weight: 1
        $x_1_2 = "Tools::IETools::`" ascii //weight: 1
        $x_1_3 = "KipodTools\\KipodTools.cpp" ascii //weight: 1
        $x_5_4 = "Only Internet Explorer code should write this" ascii //weight: 5
        $x_5_5 = "Software\\Microsoft\\Internet Explorer\\Approved Extensions" wide //weight: 5
        $n_10_6 = "Viber" ascii //weight: -10
        $n_10_7 = "Viber" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

