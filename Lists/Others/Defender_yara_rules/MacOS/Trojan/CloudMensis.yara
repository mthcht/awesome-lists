rule Trojan_MacOS_CloudMensis_A_2147827610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/CloudMensis.A!MTB"
        threat_id = "2147827610"
        type = "Trojan"
        platform = "MacOS: "
        family = "CloudMensis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncryptMyFile:encrypt:key:afterDelete" ascii //weight: 1
        $x_1_2 = "UploadFileImmediately:CMD:delete" ascii //weight: 1
        $x_1_3 = "CreatePlistFileAt:withLabel:exePath:exeType:keepAlive" ascii //weight: 1
        $x_1_4 = "ExecuteCmdAndSaveResult:saveResult:uploadImmediately" ascii //weight: 1
        $x_1_5 = "/Library/LaunchDaemons/.com.apple.WindowServer.plist" ascii //weight: 1
        $x_1_6 = "/Volumes/Data/LeonWork/MainTask/BaD/execute/execute/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MacOS_CloudMensis_B_2147828170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/CloudMensis.B!MTB"
        threat_id = "2147828170"
        type = "Trojan"
        platform = "MacOS: "
        family = "CloudMensis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Library/LaunchDaemons/.com.apple.WindowServer.plist" ascii //weight: 1
        $x_1_2 = "/Library/WebServer/share/httpd/manual/WindowServer" ascii //weight: 1
        $x_1_3 = "diskutil mount -mountPoint /tmp/mnt /dev/disk0s1" ascii //weight: 1
        $x_1_4 = "rm -f /tmp/mnt/root" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

