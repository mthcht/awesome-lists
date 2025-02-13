rule PWS_Win32_Stimilini_J_2147691946_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stimilini.J"
        threat_id = "2147691946"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 53 74 65 61 6d 43 6f 6f 6b 69 65 73}  //weight: 1, accuracy: High
        $x_1_2 = "??253763253763" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Stimilini_K_2147707680_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stimilini.K"
        threat_id = "2147707680"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "derkziel_form" wide //weight: 1
        $x_1_2 = "derkziel.txt" ascii //weight: 1
        $x_1_3 = "ssfn*" ascii //weight: 1
        $x_1_4 = "config\\SteamAppData.vdf" ascii //weight: 1
        $x_1_5 = "#!acti!#" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

