rule Trojan_AndroidOS_Starwarz_A_2147773574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Starwarz.A!MTB"
        threat_id = "2147773574"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Starwarz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "4A4El5wEF3sOjf1wmAVzWJVaRpMVL2bgVqHytv1Wbg" ascii //weight: 2
        $x_1_2 = "://montanatony.xyz/api/" ascii //weight: 1
        $x_1_3 = "doInBackground" ascii //weight: 1
        $x_1_4 = "achillies/2FA.php" ascii //weight: 1
        $x_1_5 = "FUCKING CUNT , ARE YOU DECOMPILING HUH?" ascii //weight: 1
        $x_2_6 = "SxQ2H2zl+pHxY8MZF4VY3Q" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

