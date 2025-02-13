rule Backdoor_MSIL_Darkcommet_PAGE_2147929561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Darkcommet.PAGE!MTB"
        threat_id = "2147929561"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcommet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bot/miner.php" wide //weight: 2
        $x_1_2 = "SELECT Caption FROM Win32_OperatingSystem" wide //weight: 1
        $x_1_3 = "\\root\\SecurityCenter" wide //weight: 1
        $x_2_4 = "SELECT displayName FROM AntivirusProduct" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

