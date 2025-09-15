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
        $x_1_18 = ".organzoperate.com" ascii //weight: 1
        $x_1_19 = ".ephelp.site" ascii //weight: 1
        $x_1_20 = "dcontrol.guidzin.com" ascii //weight: 1
        $x_1_21 = "docs.viewyourstatementonline.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule SupportScam_Win32_Screcwon_MD_2147947634_0
{
    meta:
        author = "defender2yara"
        detection_name = "SupportScam:Win32/Screcwon.MD!MTB"
        threat_id = "2147947634"
        type = "SupportScam"
        platform = "Win32: Windows 32-bit platform"
        family = "Screcwon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Release\\ClickOnceRunner.pdb" ascii //weight: 20
        $x_20_2 = "Release\\DotNetRunner.pdb" ascii //weight: 20
        $x_30_3 = ".filesdonwloads.com" ascii //weight: 30
        $x_30_4 = "relay.magaretcap.com" ascii //weight: 30
        $x_30_5 = "relay.shipperzone.online" ascii //weight: 30
        $x_30_6 = "fmt2as.ddns.net" ascii //weight: 30
        $x_30_7 = "app.ratoscreensell.com" ascii //weight: 30
        $x_30_8 = "relay.ale3rt.in" ascii //weight: 30
        $x_30_9 = "microsoffeedd4ackapiz.enterprisesolutions.su" ascii //weight: 30
        $x_30_10 = ".putinswin.es" ascii //weight: 30
        $x_30_11 = "dual.saltuta.com" ascii //weight: 30
        $x_30_12 = "brovanti.de" ascii //weight: 30
        $x_30_13 = ".ratoscbom.com" ascii //weight: 30
        $x_30_14 = "pulseriseglobal.com" ascii //weight: 30
        $x_30_15 = ".myedelta.de" ascii //weight: 30
        $x_30_16 = "kingcardano.io" ascii //weight: 30
        $x_30_17 = ".viewyourstatementonline.com" ascii //weight: 30
        $x_30_18 = "preyinthewild.online" ascii //weight: 30
        $x_30_19 = "download.e-statement.estate" ascii //weight: 30
        $x_30_20 = "hp.noleggiodisciza.com" ascii //weight: 30
        $x_30_21 = "dev.southsideblackancestry.com" ascii //weight: 30
        $x_30_22 = "server.ygoogley.in" ascii //weight: 30
        $x_30_23 = "camp.organzoperate.com" ascii //weight: 30
        $x_30_24 = "mail.securedocumentfiledownload.com" ascii //weight: 30
        $x_30_25 = "doc-sas.marqulsmitchel.com" ascii //weight: 30
        $x_30_26 = "jntl.shop" ascii //weight: 30
        $x_30_27 = "solandalucia-carcosmetics.com" ascii //weight: 30
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 1 of ($x_20_*))) or
            ((2 of ($x_30_*))) or
            (all of ($x*))
        )
}

