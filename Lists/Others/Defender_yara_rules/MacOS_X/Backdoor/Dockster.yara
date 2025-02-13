rule Backdoor_MacOS_X_Dockster_A_2147672237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Dockster.A"
        threat_id = "2147672237"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Dockster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "~/Library/LaunchAgents/mac.Dockset" ascii //weight: 1
        $x_1_2 = "./.Dockset  key" ascii //weight: 1
        $x_1_3 = "/mac.Dockset.deman.plist" ascii //weight: 1
        $x_1_4 = "/sbin/ifconfig en0 ether |grep ether" ascii //weight: 1
        $x_1_5 = {2f 76 61 72 2f 74 6d 70 2f [0-21] 2e 6c 63 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

