rule TrojanSpy_Win64_PrysmaxStealer_A_2147958360_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/PrysmaxStealer.A!AMTB"
        threat_id = "2147958360"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "PrysmaxStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Installed Antivirus" ascii //weight: 1
        $x_1_2 = "Cookies Found" ascii //weight: 1
        $x_1_3 = "Passwords Found" ascii //weight: 1
        $x_1_4 = "Credit Cards Found" ascii //weight: 1
        $x_1_5 = "Bookmarks Found" ascii //weight: 1
        $x_1_6 = "Telegram Session" ascii //weight: 1
        $x_1_7 = "Clipboard" ascii //weight: 1
        $x_1_8 = "History Items" ascii //weight: 1
        $x_1_9 = "Discord Tokens" ascii //weight: 1
        $x_1_10 = "App Credentials" ascii //weight: 1
        $x_2_11 = {50 72 79 73 6d 61 78 [0-5] 43 6f 6f 6b 69 65 73}  //weight: 2, accuracy: Low
        $x_1_12 = "taskkill/F/IM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

