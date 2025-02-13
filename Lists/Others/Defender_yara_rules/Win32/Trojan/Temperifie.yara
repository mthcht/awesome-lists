rule Trojan_Win32_Temperifie_A_2147637370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Temperifie.A"
        threat_id = "2147637370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Temperifie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {30 78 30 30 33 30 00 31 30 33 34 00 31 30 33 39 00 31 30 32 38 00 31 32 35 36}  //weight: 5, accuracy: High
        $x_2_2 = "permite.info/" ascii //weight: 2
        $x_1_3 = "/hvsbtn.exe" ascii //weight: 1
        $x_1_4 = "/n2stn.exe" ascii //weight: 1
        $x_1_5 = "/hkmsgr.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

