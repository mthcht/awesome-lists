rule Backdoor_WinNT_Syzor_A_2147610360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Syzor.A"
        threat_id = "2147610360"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Syzor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Zorg\\sys\\objfre\\i386\\syringe.pdb" ascii //weight: 1
        $x_1_2 = "\\BaseNamedObjects\\0x41545550" wide //weight: 1
        $x_1_3 = "services.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

