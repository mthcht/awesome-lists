rule Trojan_Win32_Visero_A_2147682638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Visero.A"
        threat_id = "2147682638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Visero"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SPREAD_SKYPE" ascii //weight: 1
        $x_1_2 = "DDOS_SIMPLE" ascii //weight: 1
        $x_1_3 = "%,BDOWNLOADER_URL" ascii //weight: 1
        $x_1_4 = "Bitte aktualisieren Sie Ihre Zahlungsdaten" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

