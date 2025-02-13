rule PWS_Win32_Qusar_RC_2147744425_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Qusar.RC!!Qusar.gen!A"
        threat_id = "2147744425"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Qusar"
        severity = "Critical"
        info = "Qusar: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_logins.txt" ascii //weight: 1
        $x_1_2 = "_ccdata.txt" ascii //weight: 1
        $x_1_3 = "_cookie.txt" ascii //weight: 1
        $x_1_4 = "ImageGrab" ascii //weight: 1
        $x_1_5 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" ascii //weight: 1
        $x_1_6 = "/AppData/Local/browsers/txt/" ascii //weight: 1
        $x_1_7 = "\\AppData\\Local\\debug.zip" ascii //weight: 1
        $x_1_8 = "\\AppData\\Local\\browsers\\screenshot.png" ascii //weight: 1
        $x_1_9 = "/Desktop/*.txt" ascii //weight: 1
        $x_1_10 = "browser_chrome" ascii //weight: 1
        $x_1_11 = "browser_folder" ascii //weight: 1
        $x_1_12 = "profile_folder" ascii //weight: 1
        $x_1_13 = "card_number_encrypted" ascii //weight: 1
        $x_1_14 = "billing_address_id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

