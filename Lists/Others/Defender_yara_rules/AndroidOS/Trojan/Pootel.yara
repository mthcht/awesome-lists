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

rule Trojan_AndroidOS_Pootel_C_2147940020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Pootel.C!MTB"
        threat_id = "2147940020"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Pootel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 01 ee 0d 1d 00 0a 04 b5 84 33 84 0f 00 6e 20 e9 0d 91 00 0a 0a 74 01 99 0e 1c 00 0a 04 db 0b 04 02 13 04 1a 00 28 04 12 04 12 0a 12 0b}  //weight: 1, accuracy: High
        $x_1_2 = {22 00 ce 01 70 10 1c 11 00 00 6e 20 1b 11 03 00 22 00 6b 03 70 10 0a 11 00 00 6e 20 19 11 03 00 6e 20 46 0f 23 00 71 10 1a 11 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

