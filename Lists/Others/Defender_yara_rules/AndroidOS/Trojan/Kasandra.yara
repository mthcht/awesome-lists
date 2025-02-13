rule Trojan_AndroidOS_Kasandra_A_2147744839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Kasandra.A!MTB"
        threat_id = "2147744839"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Kasandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "droidjack.net/Access/DJ6.php" ascii //weight: 1
        $x_1_2 = "droidjack.net/storeReport.php" ascii //weight: 1
        $x_1_3 = "/DJTmpcpDIR.zip" ascii //weight: 1
        $x_1_4 = "SandroRat_RecordedSMS_Database" ascii //weight: 1
        $x_1_5 = "SandroRat_CallRecords_Database" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

