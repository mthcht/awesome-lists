rule Trojan_MSIL_Wirzemro_A_2147723603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Wirzemro.A"
        threat_id = "2147723603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wirzemro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "127.0.0.1 cpm.paneladmin.pro" ascii //weight: 1
        $x_1_2 = "127.0.0.1 publisher.hmdiadmingate.xyz" ascii //weight: 1
        $x_1_3 = "127.0.0.1 distribution.hmdiadmingate.xyz" ascii //weight: 1
        $x_1_4 = "127.0.0.1 hmdicrewtracksystem.xyz" ascii //weight: 1
        $x_1_5 = "127.0.0.1 linkmate.space" ascii //weight: 1
        $x_1_6 = "127.0.0.1 space1.adminpressure.space" ascii //weight: 1
        $x_1_7 = "127.0.0.1 trackpressure.website" ascii //weight: 1
        $x_1_8 = "127.0.0.1 doctorlink.space" ascii //weight: 1
        $x_1_9 = "127.0.0.1 plugpackdownload.net" ascii //weight: 1
        $x_1_10 = "127.0.0.1 texttotalk.org" ascii //weight: 1
        $x_1_11 = "127.0.0.1 gambling577.xyz" ascii //weight: 1
        $x_1_12 = "127.0.0.1 htagdownload.space" ascii //weight: 1
        $x_1_13 = "127.0.0.1 mybcnmonetize.com" ascii //weight: 1
        $x_1_14 = "127.0.0.1 360devtraking.website" ascii //weight: 1
        $x_1_15 = "127.0.0.1 dscdn.pw" ascii //weight: 1
        $x_1_16 = "127.0.0.1 beautifllink.xyz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_Wirzemro_B_2147729241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Wirzemro.B"
        threat_id = "2147729241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wirzemro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cpm.paneladmin.pro" wide //weight: 1
        $x_1_2 = "publisher.hmdiadmingate.xyz" wide //weight: 1
        $x_1_3 = "hmdicrewtracksystem.xyz" wide //weight: 1
        $x_1_4 = "mydownloaddomain.com" wide //weight: 1
        $x_1_5 = "linkmate.space" wide //weight: 1
        $x_1_6 = "space1.adminpressure.space" wide //weight: 1
        $x_1_7 = "trackpressure.website" wide //weight: 1
        $x_1_8 = "doctorlink.space" wide //weight: 1
        $x_1_9 = "plugpackdownload.net" wide //weight: 1
        $x_1_10 = "texttotalk.org" wide //weight: 1
        $x_1_11 = "gambling577.xyz" wide //weight: 1
        $x_1_12 = "htagdownload.space" wide //weight: 1
        $x_1_13 = "mybcnmonetize.com" wide //weight: 1
        $x_1_14 = "360devtraking.website" wide //weight: 1
        $x_1_15 = "dscdn.pw" wide //weight: 1
        $x_1_16 = "bcnmonetize.go2affise.com" wide //weight: 1
        $x_1_17 = "beautifllink.xyz" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

