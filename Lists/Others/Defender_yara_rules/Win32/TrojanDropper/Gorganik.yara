rule TrojanDropper_Win32_Gorganik_2147654406_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Gorganik"
        threat_id = "2147654406"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Gorganik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Organik 1.00 Kurulum" ascii //weight: 1
        $x_1_2 = "Organik kurulumu" ascii //weight: 1
        $x_1_3 = "Orghitserv" ascii //weight: 1
        $x_1_4 = "Mevcut Dosya:" ascii //weight: 1
        $x_1_5 = "Yeni Dosya:" ascii //weight: 1
        $x_1_6 = "Alexa.exe" ascii //weight: 1
        $x_1_7 = "Smart Install Maker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

