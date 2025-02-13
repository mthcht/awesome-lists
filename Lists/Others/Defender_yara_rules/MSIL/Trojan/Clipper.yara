rule Trojan_MSIL_Clipper_AA_2147768526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Clipper.AA!MTB"
        threat_id = "2147768526"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "autorun_enabled" ascii //weight: 1
        $x_1_2 = "ClipboardMonitor" ascii //weight: 1
        $x_1_3 = "replace_clipboard" ascii //weight: 1
        $x_1_4 = "AppMutex" ascii //weight: 1
        $x_1_5 = "clipboard_check_delay" ascii //weight: 1
        $x_1_6 = "startup_directory" ascii //weight: 1
        $x_1_7 = "Clipper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Clipper_AB_2147775613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Clipper.AB!MTB"
        threat_id = "2147775613"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RedLine.Clipper" ascii //weight: 1
        $x_1_2 = "ClipboardWatcher" ascii //weight: 1
        $x_1_3 = "add_OnClipboardChange" ascii //weight: 1
        $x_1_4 = "ChangeClipboardChain" ascii //weight: 1
        $x_1_5 = "b(bc1|[13])[a-zA-HJ-NP-Z0-9]{26,35}\\b" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

