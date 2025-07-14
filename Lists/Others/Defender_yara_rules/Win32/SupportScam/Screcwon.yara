rule SupportScam_Win32_Screcwon_MA_2147944259_0
{
    meta:
        author = "defender2yara"
        detection_name = "SupportScam:Win32/Screcwon.MA!MTB"
        threat_id = "2147944259"
        type = "SupportScam"
        platform = "Win32: Windows 32-bit platform"
        family = "Screcwon"
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
        $x_1_9 = ".filesdonwloads.com" ascii //weight: 1
        $x_1_10 = "wizz.infinitycloud.org" ascii //weight: 1
        $x_1_11 = "llkt501.ddns.net" ascii //weight: 1
        $x_1_12 = "yourrldns22.hopto.org" ascii //weight: 1
        $x_1_13 = "wk36back966.site" ascii //weight: 1
        $x_1_14 = "void.corsazone.com" ascii //weight: 1
        $x_1_15 = "relay.ziadpaneel.com" ascii //weight: 1
        $x_1_16 = "mail.securedocumentfiledownload.com" ascii //weight: 1
        $x_1_17 = "dual.saltuta.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

