rule Trojan_Win32_CBotStealer_A_2147811207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CBotStealer.A"
        threat_id = "2147811207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CBotStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\_Files\\_Information.txt" ascii //weight: 1
        $x_1_2 = "Keyboard Languages:      " ascii //weight: 1
        $x_1_3 = "\\_Files\\_AllCookies_list.txt" ascii //weight: 1
        $x_1_4 = "\\files_\\cookies.txt" ascii //weight: 1
        $x_1_5 = "\\_Files\\_Cookies\\google_chrome.txt" ascii //weight: 1
        $x_1_6 = "\\files_\\cookies\\google_chrome_profile_2.txt" ascii //weight: 1
        $x_1_7 = "\\files_\\cryptocurrency\\" ascii //weight: 1
        $x_1_8 = "\\_Files\\_Wallet\\" ascii //weight: 1
        $x_1_9 = ".sqlite" ascii //weight: 1
        $x_1_10 = ".json" ascii //weight: 1
        $x_1_11 = "UserName (ComputerName): %wS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

