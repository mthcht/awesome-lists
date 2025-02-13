rule Trojan_Win32_Dakirke_A_2147730226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dakirke.A"
        threat_id = "2147730226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dakirke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Telefonbruseres6" ascii //weight: 1
        $x_1_2 = "mucilage" ascii //weight: 1
        $x_1_3 = "Unapprehending" ascii //weight: 1
        $x_1_4 = "kirkegaardsleders" ascii //weight: 1
        $x_1_5 = "Sirplanternes" ascii //weight: 1
        $x_1_6 = "Agonien" ascii //weight: 1
        $x_1_7 = "Exocoelom7" ascii //weight: 1
        $x_1_8 = "RAPPORTERINGERNE" ascii //weight: 1
        $x_1_9 = "Infiltre" ascii //weight: 1
        $x_1_10 = "Form_Paint" ascii //weight: 1
        $x_1_11 = "StartSysInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

