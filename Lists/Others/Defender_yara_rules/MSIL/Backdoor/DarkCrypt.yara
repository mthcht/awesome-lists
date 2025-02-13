rule Backdoor_MSIL_DarkCrypt_2147750581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DarkCrypt!MTB"
        threat_id = "2147750581"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bd.darkkkis.com" ascii //weight: 1
        $x_1_2 = "Control\\Terminal Server\\WinStations\\RDP-Tcp" ascii //weight: 1
        $x_1_3 = "dhcp.exe" ascii //weight: 1
        $x_1_4 = "dhcp.InstallLog" ascii //weight: 1
        $x_1_5 = "set_UserCannotChangePassword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

