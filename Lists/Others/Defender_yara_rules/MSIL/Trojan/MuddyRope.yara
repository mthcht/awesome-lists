rule Trojan_MSIL_MuddyRope_A_2147741353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MuddyRope.A"
        threat_id = "2147741353"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MuddyRope"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svchosts.exe" ascii //weight: 1
        $x_1_2 = "Lzc4LjEyOS4xMzkuMTQ4" wide //weight: 1
        $x_1_3 = "PS2EXEHostRawUI" ascii //weight: 1
        $x_1_4 = "ik.PowerShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

