rule Trojan_MSIL_Cfgrator_2147798827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cfgrator!MTB"
        threat_id = "2147798827"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cfgrator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<LogonTrigger>" ascii //weight: 1
        $x_1_2 = "<MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>" ascii //weight: 1
        $x_1_3 = "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>" ascii //weight: 1
        $x_1_4 = "<StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>" ascii //weight: 1
        $x_1_5 = "<AllowHardTerminate>false</AllowHardTerminate>" ascii //weight: 1
        $x_1_6 = "<StartWhenAvailable>true</StartWhenAvailable>" ascii //weight: 1
        $x_1_7 = "<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>" ascii //weight: 1
        $x_1_8 = "<AllowStartOnDemand>true</AllowStartOnDemand>" ascii //weight: 1
        $x_1_9 = "<RunOnlyIfIdle>false</RunOnlyIfIdle>" ascii //weight: 1
        $x_1_10 = "<WakeToRun>false</WakeToRun>" ascii //weight: 1
        $x_1_11 = {3c 45 78 65 63 75 74 69 6f 6e 54 69 6d 65 4c 69 6d 69 74 3e [0-16] 3c 2f 45 78 65 63 75 74 69 6f 6e 54 69 6d 65 4c 69 6d 69 74 3e}  //weight: 1, accuracy: Low
        $x_1_12 = "<Command>[LOCATION]</Command>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

