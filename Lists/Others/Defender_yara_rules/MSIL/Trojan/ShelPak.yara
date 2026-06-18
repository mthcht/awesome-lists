rule Trojan_MSIL_ShelPak_AVN_2147971912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShelPak.AVN!MTB"
        threat_id = "2147971912"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShelPak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "& del info-0v92.txt /q /s & attrib +h +s -r desktop.ini" wide //weight: 5
        $x_5_2 = "taskkill.exe /im Explorer.exe /f" wide //weight: 5
        $x_5_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

