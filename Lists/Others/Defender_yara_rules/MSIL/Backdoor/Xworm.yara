rule Backdoor_MSIL_Xworm_MK_2147973677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Xworm.MK!MTB"
        threat_id = "2147973677"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "d3c0y-1nj3ct0r!" wide //weight: 10
        $x_5_2 = "DecoyShellcodeRoutine" ascii //weight: 5
        $x_3_3 = "DecoyPersistViaService" ascii //weight: 3
        $x_2_4 = "DecoyFetchDecryp" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

