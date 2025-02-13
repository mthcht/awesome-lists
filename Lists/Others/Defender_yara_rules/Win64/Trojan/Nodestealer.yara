rule Trojan_Win64_Nodestealer_MC_2147892745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Nodestealer.MC!MTB"
        threat_id = "2147892745"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Nodestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "MicrosofOffice.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

