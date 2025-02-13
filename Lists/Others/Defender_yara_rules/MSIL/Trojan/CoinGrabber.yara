rule Trojan_MSIL_CoinGrabber_MK_2147810334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinGrabber.MK!MTB"
        threat_id = "2147810334"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinGrabber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WM_CLIPBOARDUPDATE" ascii //weight: 1
        $x_1_2 = "AddClipboardFormatListener" ascii //weight: 1
        $x_1_3 = "GetText" ascii //weight: 1
        $x_1_4 = "SetText" ascii //weight: 1
        $x_1_5 = "Bitcoin-Grabber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

