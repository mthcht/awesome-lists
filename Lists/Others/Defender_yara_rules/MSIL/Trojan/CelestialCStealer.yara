rule Trojan_MSIL_CelestialCStealer_BSA_2147933920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CelestialCStealer.BSA!MTB"
        threat_id = "2147933920"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CelestialCStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "123"
        strings_accuracy = "High"
    strings:
        $x_120_1 = "celestialC.Stealer.FTP" ascii //weight: 120
        $x_1_2 = "StealFTP" ascii //weight: 1
        $x_1_3 = "BCRYPT_PAD_PSS" ascii //weight: 1
        $x_1_4 = "celestialC.Stealer.Messenger.Discord" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CelestialCStealer_DA_2147942807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CelestialCStealer.DA!MTB"
        threat_id = "2147942807"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CelestialCStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "106"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "celestialC.Properties" ascii //weight: 100
        $x_1_2 = "GetLogicalDrives" ascii //weight: 1
        $x_1_3 = "get_AllScreens" ascii //weight: 1
        $x_1_4 = "ScreenToClient" ascii //weight: 1
        $x_1_5 = "VideoCaptureDevice" ascii //weight: 1
        $x_1_6 = "IsLogging" ascii //weight: 1
        $x_1_7 = "ComputerInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

