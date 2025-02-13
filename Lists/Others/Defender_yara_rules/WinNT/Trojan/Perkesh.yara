rule Trojan_WinNT_Perkesh_A_2147616754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Perkesh.gen!A"
        threat_id = "2147616754"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Perkesh"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RK\\objfre\\i386\\MyRootKit.pdb" ascii //weight: 1
        $x_1_2 = "\\Device\\NsRK1" wide //weight: 1
        $x_1_3 = "KeRaiseIrqlToDpcLevel" ascii //weight: 1
        $x_1_4 = "ZwOpenProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Perkesh_B_2147616755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Perkesh.gen!B"
        threat_id = "2147616755"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Perkesh"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wi0dow0\\Sy0tem32\\0lg.exe" wide //weight: 1
        $x_1_2 = "Ps1\\Driver\\i386\\Killer.pdb" ascii //weight: 1
        $x_1_3 = "\\DosDevices\\0ciFt0isk" wide //weight: 1
        $x_1_4 = "KdDisableDebugger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

