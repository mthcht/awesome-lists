rule Backdoor_MSIL_Muddywat_A_2147731131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Muddywat.A!MTB"
        threat_id = "2147731131"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Muddywat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//wp-config-ini.php" wide //weight: 1
        $x_1_2 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" wide //weight: 1
        $x_1_3 = "api.ipify.org" wide //weight: 1
        $x_1_4 = "bluescreen" wide //weight: 1
        $x_1_5 = "COMMAND" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

