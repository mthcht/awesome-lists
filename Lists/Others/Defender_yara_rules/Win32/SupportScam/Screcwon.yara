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
        threshold = "120"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Source\\cwcontrol\\Misc\\Bootstrapper\\Release\\ClickOnceRunner.pdb" ascii //weight: 20
        $x_20_2 = "Source\\cwcontrol\\Custom\\DotNetRunner\\Release\\DotNetRunner.pdb" ascii //weight: 20
        $x_20_3 = "Source\\ScreenConnectWork\\Custom\\DotNetRunner\\Release\\DotNetRunner.pdb" ascii //weight: 20
        $x_100_4 = ".top&p=8880" ascii //weight: 100
        $x_100_5 = ".innocreed.com" ascii //weight: 100
        $x_100_6 = ".controlhub.es" ascii //weight: 100
        $x_100_7 = ".ratoscreenco.com" ascii //weight: 100
        $x_100_8 = ".screensconnectpro.com" ascii //weight: 100
        $x_100_9 = "slplegalfinance.com" ascii //weight: 100
        $x_100_10 = ".filesdonwloads.com" ascii //weight: 100
        $x_100_11 = "wizz.infinitycloud.org" ascii //weight: 100
        $x_100_12 = "llkt501.ddns.net" ascii //weight: 100
        $x_100_13 = "yourrldns22.hopto.org" ascii //weight: 100
        $x_100_14 = "wk36back966.site" ascii //weight: 100
        $x_100_15 = "void.corsazone.com" ascii //weight: 100
        $x_100_16 = "relay.ziadpaneel.com" ascii //weight: 100
        $x_100_17 = "mail.securedocumentfiledownload.com" ascii //weight: 100
        $x_100_18 = "dual.saltuta.com" ascii //weight: 100
        $x_100_19 = ".organzoperate.com" ascii //weight: 100
        $x_100_20 = ".ephelp.site" ascii //weight: 100
        $x_100_21 = "dcontrol.guidzin.com" ascii //weight: 100
        $x_100_22 = "docs.viewyourstatementonline.com" ascii //weight: 100
        $x_100_23 = "olphelp.top" ascii //weight: 100
        $x_100_24 = "tbaysupport.ca" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_20_*))) or
            ((2 of ($x_100_*))) or
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
        $x_30_28 = "dynomar.gandizon.com" ascii //weight: 30
        $x_30_29 = "bw36back93.site" ascii //weight: 30
        $x_30_30 = "fw396back6.site" ascii //weight: 30
        $x_30_31 = "relay.adobpdf.com" ascii //weight: 30
        $x_30_32 = "sent.costariga.de" ascii //weight: 30
        $x_30_33 = "pilwerui.rchelp.top" ascii //weight: 30
        $x_30_34 = "rwbhelp.top" ascii //weight: 30
        $x_30_35 = "zvhelp.top" ascii //weight: 30
        $x_30_36 = "wyghelp.top" ascii //weight: 30
        $x_30_37 = "ofhelp.top" ascii //weight: 30
        $x_30_38 = "kcclive.top" ascii //weight: 30
        $x_30_39 = "mango.quatrocliche.com" ascii //weight: 30
        $x_30_40 = "molatoriism.icu" ascii //weight: 30
        $x_30_41 = "onyxsupportx.de" ascii //weight: 30
        $x_30_42 = "onyxfortitech.de" ascii //weight: 30
        $x_30_43 = "onyxnexguard.de" ascii //weight: 30
        $x_30_44 = "onyxaquarius.top" ascii //weight: 30
        $x_30_45 = "engajroker.cyou" ascii //weight: 30
        $x_30_46 = "mail.ssadownload.top" ascii //weight: 30
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 1 of ($x_20_*))) or
            ((2 of ($x_30_*))) or
            (all of ($x*))
        )
}

