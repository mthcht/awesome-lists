rule Trojan_MSIL_DarkCrystal_SBR_2147762346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCrystal.SBR!MSR"
        threat_id = "2147762346"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCrystal"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keyloggerdata" wide //weight: 1
        $x_1_2 = "config/loginusers.vdf" wide //weight: 1
        $x_1_3 = "Steal Browsers" wide //weight: 1
        $x_1_4 = "Grabbing cookies" wide //weight: 1
        $x_1_5 = "Fetching passwords" wide //weight: 1
        $x_1_6 = "Browsers/Unknowns/Cookies" wide //weight: 1
        $x_1_7 = "Browsers/Unknowns/Passwords" wide //weight: 1
        $x_1_8 = "Windows Domain Password Credential" wide //weight: 1
        $x_1_9 = "SELECT * FROM AntivirusProduct" wide //weight: 1
        $x_1_10 = "SELECT * FROM FirewallProduct" wide //weight: 1
        $x_1_11 = "SELECT * FROM Win32_BIOS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

