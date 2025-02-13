rule Ransom_MacOS_Kuiper_A_2147902048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/Kuiper.A!MTB"
        threat_id = "2147902048"
        type = "Ransom"
        platform = "MacOS: "
        family = "Kuiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/root/kuiper" ascii //weight: 1
        $x_1_2 = "main.RunSafeModeAndGetAdminPrivileges" ascii //weight: 1
        $x_1_3 = "main.CleanMemoryKey" ascii //weight: 1
        $x_1_4 = "README_TO_DECRYPT.txt" ascii //weight: 1
        $x_1_5 = "main.StartAllBypass" ascii //weight: 1
        $x_1_6 = "main.RenameAllFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

