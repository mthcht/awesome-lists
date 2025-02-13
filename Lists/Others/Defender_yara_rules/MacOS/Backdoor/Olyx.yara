rule Backdoor_MacOS_Olyx_2147735558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Olyx"
        threat_id = "2147735558"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Olyx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/Users/yxl/Documents/Xcode/macpak/main.c" ascii //weight: 2
        $x_2_2 = "/tmp/google.tmp" ascii //weight: 2
        $x_2_3 = "/Library/LaunchAgents/www.google.com.tstart.plist" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_Olyx_C_2147749357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Olyx.C!MTB"
        threat_id = "2147749357"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Olyx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mail.tbnewspaper.com" ascii //weight: 1
        $x_1_2 = "com.apple.docserver" ascii //weight: 1
        $x_1_3 = "/Library/LaunchAgents/com.apple.AudioService.plist" ascii //weight: 1
        $x_1_4 = "Plug-Ins/Components/AudioService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

