rule Backdoor_MSIL_Kryptik_A_2147747939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Kryptik.A!MSR"
        threat_id = "2147747939"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vmtoolsd" wide //weight: 1
        $x_1_2 = "VBoxTray" wide //weight: 1
        $x_1_3 = "WinDriv.url" wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "C choice /C Y /N /D Y /T 3 & Del" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

