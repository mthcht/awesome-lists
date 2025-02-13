rule BrowserModifier_Win32_Favoriteman_5211_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Favoriteman"
        threat_id = "5211"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Favoriteman"
        severity = "35"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Favorite.FavoriteMan.1" wide //weight: 5
        $x_1_2 = "www.f1organizer.com" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_5 = "Internet Account Manager\\Accounts\\" ascii //weight: 1
        $x_1_6 = "Microsoft\\OutLook Express\\" ascii //weight: 1
        $x_1_7 = "\\FavBoot.dll" ascii //weight: 1
        $x_1_8 = "\\Ofrg.dll" ascii //weight: 1
        $x_1_9 = "\\FavMan.dll" ascii //weight: 1
        $x_1_10 = "\\Favorite.dll" ascii //weight: 1
        $x_1_11 = "Hara Hara Mahadev !!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

