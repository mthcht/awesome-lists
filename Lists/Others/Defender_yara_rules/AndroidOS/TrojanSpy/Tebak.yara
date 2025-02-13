rule TrojanSpy_AndroidOS_Tebak_A_2147829709_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Tebak.A!MTB"
        threat_id = "2147829709"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Tebak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "send_phonlist.php" ascii //weight: 1
        $x_1_2 = "send_sim_no.php" ascii //weight: 1
        $x_1_3 = "printBankInfo=" ascii //weight: 1
        $x_1_4 = "send_bank.php" ascii //weight: 1
        $x_1_5 = "bank mobile" ascii //weight: 1
        $x_1_6 = "ttp://M.UPLOUS.NET/" ascii //weight: 1
        $x_1_7 = "Lcom/eric/tnt2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_Tebak_B_2147833985_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Tebak.B!MTB"
        threat_id = "2147833985"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Tebak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/woorinewbank" ascii //weight: 1
        $x_1_2 = "WooriPswDetail" ascii //weight: 1
        $x_1_3 = "uploadBandData" ascii //weight: 1
        $x_1_4 = "WooriCertAdapter" ascii //weight: 1
        $x_1_5 = "send_bank.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Tebak_C_2147841244_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Tebak.C!MTB"
        threat_id = "2147841244"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Tebak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InfoGetter" ascii //weight: 1
        $x_1_2 = "banknumpw" ascii //weight: 1
        $x_1_3 = "/upload.php" ascii //weight: 1
        $x_1_4 = "/send_bank.php" ascii //weight: 1
        $x_1_5 = "send_sim_no" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

