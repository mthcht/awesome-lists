rule Backdoor_Win32_Briewots_A_2147646371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Briewots.A"
        threat_id = "2147646371"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Briewots"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 72 6f 77 73 65 49 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "IGNORE6=javascript:history.back(1)" ascii //weight: 1
        $x_1_3 = "RestartAllProject_ONLYifipADDRESS_or_LuckyURL2visit_Found=yes" ascii //weight: 1
        $x_1_4 = "AllowedCountries=RU, US, GB, CA," ascii //weight: 1
        $x_1_5 = "ExecuteFiles. File:" wide //weight: 1
        $x_1_6 = "/geo/countrybyip.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

