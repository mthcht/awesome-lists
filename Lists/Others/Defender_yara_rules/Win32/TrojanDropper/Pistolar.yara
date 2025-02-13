rule TrojanDropper_Win32_Pistolar_AA_2147747926_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Pistolar.AA!MTB"
        threat_id = "2147747926"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Pistolar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\svhost.exe" wide //weight: 1
        $x_1_2 = "kaspersky" wide //weight: 1
        $x_1_3 = "virut" wide //weight: 1
        $x_1_4 = "trojan" wide //weight: 1
        $x_1_5 = "anti-virus" wide //weight: 1
        $x_1_6 = "malware" wide //weight: 1
        $x_1_7 = "Windows Task Manager" wide //weight: 1
        $x_1_8 = "\\Driver.db" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

