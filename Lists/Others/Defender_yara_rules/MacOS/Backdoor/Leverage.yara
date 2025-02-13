rule Backdoor_MacOS_Leverage_A_2147747963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Leverage.A!MTB"
        threat_id = "2147747963"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Leverage"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rm '/Users/Shared/UserEvent.app/Contents/Resources/UserEvent.icns'" ascii //weight: 1
        $x_1_2 = "osascript -e 'tell application \"System Events\" to get the hidden of every login item'" ascii //weight: 1
        $x_1_3 = "osascript -e 'input volume of (get volume settings)'" ascii //weight: 1
        $x_1_4 = "Macintosh HD:Users:Shared:up.zip" ascii //weight: 1
        $x_1_5 = {61 77 6b 20 2d 46 27 3a 5c 74 27 20 27 7b 70 72 69 6e 74 20 [0-2] 7d 27 20 7c 20 70 61 73 74 65 20 2d 64}  //weight: 1, accuracy: Low
        $x_1_6 = "serverVisible" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

