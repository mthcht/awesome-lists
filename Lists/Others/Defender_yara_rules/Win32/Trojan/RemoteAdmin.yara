rule Trojan_Win32_RemoteAdmin_PAGO_2147942955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemoteAdmin.PAGO!MTB"
        threat_id = "2147942955"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemoteAdmin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "?h=relay.vahelps.top&amp;p=8041&" ascii //weight: 5
        $x_5_2 = "?h=relay.vahelps.top&amp;p=443&" ascii //weight: 5
        $x_3_3 = "DotNetRunner.pdb" ascii //weight: 3
        $x_3_4 = "ClickOnceRunner.pdb" ascii //weight: 3
        $x_1_5 = "ScreenConnect.ClientInstallerRunner.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

