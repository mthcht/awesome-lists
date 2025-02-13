rule Rogue_Win32_Quamatix_213963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Quamatix"
        threat_id = "213963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Quamatix"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 00 43 00 4d 00 41 00 54 00 49 00 43 00 50 00 4c 00 55 00 53 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {46 6f 72 6d 5f 57 61 72 6e 69 6e 67 53 63 61 6e 46 69 78 00}  //weight: 1, accuracy: High
        $x_1_3 = "System may be infected with Malicious programs" wide //weight: 1
        $x_1_4 = "Call Certified Technicians Now !" wide //weight: 1
        $x_1_5 = "/OpenPingPopup?macadd=" wide //weight: 1
        $x_1_6 = "virusIEFilter" wide //weight: 1
        $x_1_7 = "823755d2-6055-443d-a48a-505c7b89bd1e" ascii //weight: 1
        $x_2_8 = "http://pcmaticplus.com/success.html" wide //weight: 2
        $x_1_9 = "pctuner/ExeUrl?mac_add=" wide //weight: 1
        $x_1_10 = "POPUP_ALERT_PARAMETER" ascii //weight: 1
        $x_1_11 = "virusIEFilter.exe" ascii //weight: 1
        $x_2_12 = "\\infodts.dat" wide //weight: 2
        $x_1_13 = "Cleaning malicious programs, Relax..." wide //weight: 1
        $x_1_14 = "Fail to Fix. Please Retry with Correct Key" wide //weight: 1
        $x_1_15 = "pctuner/SaveAdd?productKey=" wide //weight: 1
        $x_1_16 = "System critically infected with Trojans." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

