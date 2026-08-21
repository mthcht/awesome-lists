rule Trojan_MSIL_ObfLoader_GVN_2147976613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ObfLoader.GVN!MTB"
        threat_id = "2147976613"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ObfLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-NoProfile -ExecutionPolicy Bypass -Command \"" wide //weight: 10
        $x_10_2 = "Marshal" ascii //weight: 10
        $x_10_3 = "GetByteArrayAsync" ascii //weight: 10
        $x_10_4 = "Add-MpPreference -ExclusionPath \"$env:LOCALAPPDATA\\" wide //weight: 10
        $x_10_5 = "CallWindowProcW" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

