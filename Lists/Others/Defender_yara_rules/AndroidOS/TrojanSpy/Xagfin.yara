rule TrojanSpy_AndroidOS_Xagfin_A_2147762989_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Xagfin.A!MTB"
        threat_id = "2147762989"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Xagfin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lmil/poprD30/" ascii //weight: 1
        $x_1_2 = "KOD_activ_POPR_D" ascii //weight: 1
        $x_1_3 = "AllAboutPhoneCmd" ascii //weight: 1
        $x_1_4 = "fetchContacts" ascii //weight: 1
        $x_1_5 = "CMD 101 success" ascii //weight: 1
        $x_1_6 = "***SMS History***" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

