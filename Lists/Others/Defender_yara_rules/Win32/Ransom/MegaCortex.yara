rule Ransom_Win32_Megacortex_B_2147741495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Megacortex.B"
        threat_id = "2147741495"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Megacortex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ABADAN PIZZA LTD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Megacortex_E_2147742947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Megacortex.E!MSR"
        threat_id = "2147742947"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Megacortex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".megac0rtx" wide //weight: 1
        $x_1_2 = ".m3gac0rtx" wide //weight: 1
        $x_1_3 = "vssadmin delete shadows" ascii //weight: 1
        $x_1_4 = "%1% delete shadows /all /quiet" wide //weight: 1
        $x_1_5 = "infected with MegaCortex Malware" ascii //weight: 1
        $x_1_6 = "we've hacked your corporate network" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

