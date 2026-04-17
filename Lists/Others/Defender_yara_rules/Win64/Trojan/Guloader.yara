rule Trojan_Win64_Guloader_RR_2147967208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Guloader.RR!MTB"
        threat_id = "2147967208"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ukvemsordets pertusariaceae ondulation" wide //weight: 1
        $x_1_2 = "subsidierings srskrivningernes" wide //weight: 1
        $x_1_3 = "enwoven forivrelsens skepsis" wide //weight: 1
        $x_1_4 = "knuselsker tiggermunks reemerge" wide //weight: 1
        $x_1_5 = "Troopships@Mishagsytringern.Mi1" ascii //weight: 1
        $x_1_6 = "Overexpectant1" ascii //weight: 1
        $x_1_7 = "Medskabning Konger Skose 1" ascii //weight: 1
        $x_1_8 = "Overexpectant" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

