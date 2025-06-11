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

rule Trojan_Win32_RemoteAdmin_MA_2147943374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemoteAdmin.MA!MTB"
        threat_id = "2147943374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemoteAdmin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "C:\\Users\\jmorgan\\Source\\cwcontrol\\Misc\\Bootstrapper\\Release\\ClickOnceRunner.pdb" ascii //weight: 20
        $x_20_2 = "C:\\Users\\jmorgan\\Source\\cwcontrol\\Custom\\DotNetRunner\\Release\\DotNetRunner.pdb" ascii //weight: 20
        $x_1_3 = ".top" ascii //weight: 1
        $x_1_4 = ".innocreed.com" ascii //weight: 1
        $x_1_5 = ".controlhub.es" ascii //weight: 1
        $x_1_6 = ".ratoscreenco.com" ascii //weight: 1
        $x_1_7 = ".screensconnectpro.com" ascii //weight: 1
        $x_1_8 = "slplegalfinance.com" ascii //weight: 1
        $x_1_9 = "mail.filesdonwloads.com" ascii //weight: 1
        $x_1_10 = "wizz.infinitycloud.org" ascii //weight: 1
        $x_1_11 = "llkt501.ddns.net" ascii //weight: 1
        $x_1_12 = "yourrldns22.hopto.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

