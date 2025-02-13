rule PWS_Win32_RacoonStealer_MK_2147780036_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/RacoonStealer.MK!MTB"
        threat_id = "2147780036"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "RacoonStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "560"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Google\\Chrome\\User Data" ascii //weight: 1
        $x_1_2 = "Microsoft\\Edge\\User Data" ascii //weight: 1
        $x_1_3 = "Chromium\\User Data" ascii //weight: 1
        $x_1_4 = "Xpom\\User Data" ascii //weight: 1
        $x_1_5 = "Comodo\\Dragon\\User Data" ascii //weight: 1
        $x_1_6 = "Amigo\\User Data" ascii //weight: 1
        $x_1_7 = "Orbitum\\User Data" ascii //weight: 1
        $x_1_8 = "Bromium\\User Data" ascii //weight: 1
        $x_1_9 = "BraveSoftware\\Brave-Browser\\User Data" ascii //weight: 1
        $x_1_10 = "Nichrome\\User Data" ascii //weight: 1
        $x_1_11 = "RockMelt\\User Data" ascii //weight: 1
        $x_1_12 = "360Browser\\Browser\\User Data" ascii //weight: 1
        $x_1_13 = "Vivaldi\\User Data" ascii //weight: 1
        $x_1_14 = "Go!\\User Data" ascii //weight: 1
        $x_1_15 = "Sputnik\\Sputnik\\User Data" ascii //weight: 1
        $x_1_16 = "Kometa\\User Data" ascii //weight: 1
        $x_1_17 = "uCozMedia\\Uran\\User Data" ascii //weight: 1
        $x_1_18 = "QIP Surf\\User Data" ascii //weight: 1
        $x_1_19 = "Epic Privacy Browser\\User Data" ascii //weight: 1
        $x_1_20 = "CocCoc\\Browser\\User Data" ascii //weight: 1
        $x_1_21 = "CentBrowser\\User Data" ascii //weight: 1
        $x_1_22 = "7Star\\7Star\\User Data" ascii //weight: 1
        $x_1_23 = "Elements Browser\\User Data" ascii //weight: 1
        $x_1_24 = "Suhba\\User Data" ascii //weight: 1
        $x_1_25 = "Safer Technologies\\Secure Browser\\User Data" ascii //weight: 1
        $x_1_26 = "Rafotech\\Mustang\\User Data" ascii //weight: 1
        $x_1_27 = "Superbird\\User Data" ascii //weight: 1
        $x_1_28 = "Chedot\\User Data" ascii //weight: 1
        $x_1_29 = "Torch\\User Data" ascii //weight: 1
        $x_1_30 = "Tencent\\QQBrowser\\User Data" ascii //weight: 1
        $x_50_31 = "Login Data" ascii //weight: 50
        $x_50_32 = "Cookies" ascii //weight: 50
        $x_50_33 = "Web Data" ascii //weight: 50
        $x_50_34 = "image/jpeg" ascii //weight: 50
        $x_50_35 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" ascii //weight: 50
        $x_50_36 = "Microsoft_WinInet_" ascii //weight: 50
        $x_50_37 = "inetcomm server passwords" ascii //weight: 50
        $x_50_38 = "outlook account manager passwords" ascii //weight: 50
        $x_50_39 = "data.json" ascii //weight: 50
        $x_50_40 = "screen.jpeg" ascii //weight: 50
        $x_50_41 = "machineinfo.txt" ascii //weight: 50
        $x_50_42 = "wallets" ascii //weight: 50
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_50_*) and 10 of ($x_1_*))) or
            ((12 of ($x_50_*))) or
            (all of ($x*))
        )
}

