rule Backdoor_Win32_Irchack_2147572946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Irchack"
        threat_id = "2147572946"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Irchack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Sexy Screensaver For You, delivered by a friend" ascii //weight: 3
        $x_3_2 = "Check what i found. Its saved in PIF format (Picture image Format)" ascii //weight: 3
        $x_3_3 = "Someone sent you a sexy screensaver" ascii //weight: 3
        $x_2_4 = "autoemail@screensaver.com" ascii //weight: 2
        $x_3_5 = "MSNPasswordStealer_Setup.exe" ascii //weight: 3
        $x_2_6 = "MSNHack.exe" ascii //weight: 2
        $x_2_7 = "AOL_Hack.exe" ascii //weight: 2
        $x_3_8 = "AOL_Password_Stealer.exe" ascii //weight: 3
        $x_1_9 = "ihavenopass" ascii //weight: 1
        $x_1_10 = "godblessyou" ascii //weight: 1
        $x_1_11 = "potatismos" ascii //weight: 1
        $x_1_12 = "korvmannen" ascii //weight: 1
        $x_1_13 = "wiihiee" ascii //weight: 1
        $x_1_14 = "darkarchangel" ascii //weight: 1
        $x_1_15 = "pyr0maniac" ascii //weight: 1
        $x_1_16 = "teh_puppeteer" ascii //weight: 1
        $x_1_17 = "xiao_wei" ascii //weight: 1
        $x_1_18 = "starlite_45" ascii //weight: 1
        $x_1_19 = ":[HTTP] Downloading File (" ascii //weight: 1
        $x_1_20 = ":[HTTP] Downloading Update (" ascii //weight: 1
        $x_1_21 = ":[HTTP] Downloaded" ascii //weight: 1
        $x_1_22 = ":[HTTP] Opened" ascii //weight: 1
        $x_1_23 = ":[HTTP] Failed To Open" ascii //weight: 1
        $x_1_24 = ":[HTTP] Download Failed" ascii //weight: 1
        $x_1_25 = ":[HTTP] Visit Successfull" ascii //weight: 1
        $x_1_26 = ":[HTTP] Visit Failed" ascii //weight: 1
        $x_2_27 = ":[Keygrab] User wrote \"login\"; http:" ascii //weight: 2
        $x_3_28 = ":[Keylogger] Max-size of logfile reached. Saved as (st.log-backup)" ascii //weight: 3
        $x_2_29 = "\\slugsend\\death-ap100s" ascii //weight: 2
        $x_2_30 = "\\slugsend\\death-apc" ascii //weight: 2
        $x_2_31 = "\\slugsend\\death-apb" ascii //weight: 2
        $x_2_32 = "\\slugsend\\death-aps" ascii //weight: 2
        $x_2_33 = "\\slugsend\\death-ap100s0ACEE761" ascii //weight: 2
        $x_2_34 = "-:bd:-" ascii //weight: 2
        $x_2_35 = "-:INSTALLONLY" ascii //weight: 2
        $x_2_36 = "-:REFRESH" ascii //weight: 2
        $x_2_37 = "-:NOSERVICE" ascii //weight: 2
        $x_2_38 = "-:UNINSTALL" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_2_*) and 18 of ($x_1_*))) or
            ((12 of ($x_2_*) and 16 of ($x_1_*))) or
            ((13 of ($x_2_*) and 14 of ($x_1_*))) or
            ((14 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_3_*) and 10 of ($x_2_*) and 17 of ($x_1_*))) or
            ((1 of ($x_3_*) and 11 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_3_*) and 12 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_3_*) and 13 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_3_*) and 14 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_3_*) and 8 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_3_*) and 9 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_3_*) and 10 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_3_*) and 11 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_3_*) and 12 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_3_*) and 13 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_3_*) and 14 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_3_*) and 7 of ($x_2_*) and 17 of ($x_1_*))) or
            ((3 of ($x_3_*) and 8 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_3_*) and 9 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_3_*) and 10 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_3_*) and 11 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_3_*) and 12 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_3_*) and 13 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 14 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_3_*) and 5 of ($x_2_*) and 18 of ($x_1_*))) or
            ((4 of ($x_3_*) and 6 of ($x_2_*) and 16 of ($x_1_*))) or
            ((4 of ($x_3_*) and 7 of ($x_2_*) and 14 of ($x_1_*))) or
            ((4 of ($x_3_*) and 8 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_3_*) and 9 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_3_*) and 10 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_3_*) and 11 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_3_*) and 12 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_3_*) and 13 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 14 of ($x_2_*))) or
            ((5 of ($x_3_*) and 4 of ($x_2_*) and 17 of ($x_1_*))) or
            ((5 of ($x_3_*) and 5 of ($x_2_*) and 15 of ($x_1_*))) or
            ((5 of ($x_3_*) and 6 of ($x_2_*) and 13 of ($x_1_*))) or
            ((5 of ($x_3_*) and 7 of ($x_2_*) and 11 of ($x_1_*))) or
            ((5 of ($x_3_*) and 8 of ($x_2_*) and 9 of ($x_1_*))) or
            ((5 of ($x_3_*) and 9 of ($x_2_*) and 7 of ($x_1_*))) or
            ((5 of ($x_3_*) and 10 of ($x_2_*) and 5 of ($x_1_*))) or
            ((5 of ($x_3_*) and 11 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_3_*) and 12 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_3_*) and 13 of ($x_2_*))) or
            ((6 of ($x_3_*) and 2 of ($x_2_*) and 18 of ($x_1_*))) or
            ((6 of ($x_3_*) and 3 of ($x_2_*) and 16 of ($x_1_*))) or
            ((6 of ($x_3_*) and 4 of ($x_2_*) and 14 of ($x_1_*))) or
            ((6 of ($x_3_*) and 5 of ($x_2_*) and 12 of ($x_1_*))) or
            ((6 of ($x_3_*) and 6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((6 of ($x_3_*) and 7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((6 of ($x_3_*) and 8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((6 of ($x_3_*) and 9 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_3_*) and 10 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_3_*) and 11 of ($x_2_*))) or
            (all of ($x*))
        )
}

