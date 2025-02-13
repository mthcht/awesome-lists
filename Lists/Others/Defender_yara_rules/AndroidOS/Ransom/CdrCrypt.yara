rule Ransom_AndroidOS_CdrCrypt_A_2147771358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/CdrCrypt.A!MTB"
        threat_id = "2147771358"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "CdrCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".coderCrypt" ascii //weight: 2
        $x_1_2 = "CoderWare uses a basic encryption script to lock your files" ascii //weight: 1
        $x_1_3 = "you got hit by CoderWare" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

