rule Trojan_MSIL_ShellLocker_RPW_2147823852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellLocker.RPW!MTB"
        threat_id = "2147823852"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "easyexploits.com" wide //weight: 1
        $x_1_2 = "FurkByteCode.dll" wide //weight: 1
        $x_1_3 = "is injecting..." wide //weight: 1
        $x_1_4 = "fashionablegangsterexplosion.com" wide //weight: 1
        $x_1_5 = "inieasy.lua" wide //weight: 1
        $x_1_6 = "LoadLibraryA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

