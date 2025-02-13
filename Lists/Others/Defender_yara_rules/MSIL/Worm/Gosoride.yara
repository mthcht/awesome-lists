rule Worm_MSIL_Gosoride_A_2147685556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Gosoride.A"
        threat_id = "2147685556"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gosoride"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "USB infection is on..." wide //weight: 1
        $x_1_2 = "Logging autostart is on..." wide //weight: 1
        $x_1_3 = "Infector.NetInfectionThreadModule:" wide //weight: 1
        $x_1_4 = "FileMan.ProKill:" wide //weight: 1
        $x_1_5 = "Install.SetRegistryStartup:" wide //weight: 1
        $x_1_6 = "KeyCap.StartLogging:" wide //weight: 1
        $x_1_7 = "Slave.OpenFirewall:" wide //weight: 1
        $x_1_8 = "MediaMan.ScreenShot:" wide //weight: 1
        $x_1_9 = "USBDetect.CheckDrives:" wide //weight: 1
        $x_1_10 = "Sender.SendFTP:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

