rule PWS_MSIL_Grozlex_A_2147651265_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Grozlex.A"
        threat_id = "2147651265"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Grozlex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "<HTML><HEAD></HEAD><Body BGColor=\"Black\"><font color=\"orange\"><center><h1>iCozen Logs of" wide //weight: 4
        $x_2_2 = "<br>============== Windows Key ==============<br>" wide //weight: 2
        $x_1_3 = "\\Opera\\Opera\\profile\\wand.dat" wide //weight: 1
        $x_2_4 = "?action=add&a=7&c=" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Grozlex_A_2147654735_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Grozlex.gen!A"
        threat_id = "2147654735"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Grozlex"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 08 11 05 94 06 11 05 94 61 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0d 11 05 17 d6 13 05 11 05 11 08 31 da}  //weight: 10, accuracy: Low
        $x_10_2 = {20 d2 04 00 00 20 0f 27 00 00 6f ?? ?? ?? ?? 28 ?? ?? ?? ?? 06 06 72}  //weight: 10, accuracy: Low
        $x_10_3 = {2a 09 23 00 00 00 00 d0 12 63 41 34 21 02 6c ?? 6c 5b ?? 6c 5b 13 04 12 04 72}  //weight: 10, accuracy: Low
        $x_10_4 = "?action=add&a=" wide //weight: 10
        $x_5_5 = "<Host>(.+?)</Host>\\s+<Port>(.+?)</Port>\\s+.+\\s+.+\\s+<User>(.+?)</User>\\s+<Pass>(.+?)</Pass>" wide //weight: 5
        $x_5_6 = "[Clipboard Text" wide //weight: 5
        $x_5_7 = "Keyboard Keylogs" wide //weight: 5
        $x_5_8 = ": Microsoft Windows Product Key -" wide //weight: 5
        $x_5_9 = ": Mozilla Firefox Passwords -" wide //weight: 5
        $x_1_10 = "\\Trillian\\users\\global\\accounts.ini" wide //weight: 1
        $x_1_11 = "\\config\\SteamAppData.vdf" wide //weight: 1
        $x_1_12 = "\\Bitcoin\\wallet.dat" wide //weight: 1
        $x_1_13 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 4 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

