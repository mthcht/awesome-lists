rule Trojan_AndroidOS_Pootel_A_2147829871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Pootel.A!MTB"
        threat_id = "2147829871"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Pootel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "modobom/sub/MainActivity" ascii //weight: 2
        $x_2_2 = "tikitaka/sub/MainActivity" ascii //weight: 2
        $x_1_3 = "modobom.services/api" ascii //weight: 1
        $x_1_4 = "/ConfirmSmsReceiver" ascii //weight: 1
        $x_1_5 = "sendTextMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Pootel_B_2147842918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Pootel.B!MTB"
        threat_id = "2147842918"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Pootel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "apichecksubs.modobomco.com" ascii //weight: 1
        $x_1_2 = "com/check-subs?country" ascii //weight: 1
        $x_1_3 = "ConfirmSmsReceiver" ascii //weight: 1
        $x_1_4 = "SIMOPERA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Pootel_M_2147898983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Pootel.M"
        threat_id = "2147898983"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Pootel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "User khong bam gui" ascii //weight: 1
        $x_1_2 = "Digi_Mobil_22605" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

