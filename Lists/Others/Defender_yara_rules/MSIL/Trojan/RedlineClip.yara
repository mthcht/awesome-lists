rule Trojan_MSIL_RedlineClip_GA_2147773586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineClip.GA!MTB"
        threat_id = "2147773586"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineClip"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RedLine.Clipper" ascii //weight: 1
        $x_1_2 = "DogeCoin" ascii //weight: 1
        $x_1_3 = "ZCash" ascii //weight: 1
        $x_1_4 = "Wallet" ascii //weight: 1
        $x_1_5 = "ClipboardWatcher" ascii //weight: 1
        $x_1_6 = "WM_DRAWCLIPBOARD" ascii //weight: 1
        $x_1_7 = "OnClipboardChange" ascii //weight: 1
        $x_1_8 = "regex" ascii //weight: 1
        $x_1_9 = "SetClipboardViewer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

