rule PWS_MSIL_Mercurial_GA_2147782223_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Mercurial.GA!MTB"
        threat_id = "2147782223"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mercurial"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "- mercurial grabber -" ascii //weight: 10
        $x_10_2 = "Stealer" ascii //weight: 10
        $x_1_3 = "Grabber" ascii //weight: 1
        $x_1_4 = "Roblox" ascii //weight: 1
        $x_1_5 = "DetectDebug" ascii //weight: 1
        $x_1_6 = "Minecraft" ascii //weight: 1
        $x_1_7 = "vmware" ascii //weight: 1
        $x_1_8 = "virtualbox" ascii //weight: 1
        $x_1_9 = "Capture.jpg" ascii //weight: 1
        $x_1_10 = "\\cookies.txt" ascii //weight: 1
        $x_1_11 = "passwords.txt" ascii //weight: 1
        $x_1_12 = "phone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

