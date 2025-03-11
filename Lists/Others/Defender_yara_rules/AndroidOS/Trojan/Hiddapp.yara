rule Trojan_AndroidOS_Hiddapp_B_2147812805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hiddapp.B!MTB"
        threat_id = "2147812805"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hiddapp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/api.telegram.org/bot" ascii //weight: 1
        $x_1_2 = "/sendmessage" ascii //weight: 1
        $x_1_3 = "acc.txt" ascii //weight: 1
        $x_1_4 = "/rat/upload_file.php" ascii //weight: 1
        $x_1_5 = "b4a.example.botcontril" ascii //weight: 1
        $x_1_6 = "numbers.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_Hiddapp_C_2147836800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hiddapp.C!MTB"
        threat_id = "2147836800"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hiddapp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main/AdsActivity" ascii //weight: 1
        $x_1_2 = "setAPKClassLoader" ascii //weight: 1
        $x_1_3 = "startAdsActivity" ascii //weight: 1
        $x_1_4 = "isemulator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Hiddapp_D_2147836882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hiddapp.D!MTB"
        threat_id = "2147836882"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hiddapp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "android/support/v7/app/receivers" ascii //weight: 2
        $x_2_2 = "setVmPolicy" ascii //weight: 2
        $x_1_3 = "HardwareIds" ascii //weight: 1
        $x_1_4 = "DexClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Hiddapp_H_2147896836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hiddapp.H"
        threat_id = "2147896836"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hiddapp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SHOW_USER_VP_EXPIRE" ascii //weight: 2
        $x_2_2 = "OPEN_MIDDLE_AD_MK" ascii //weight: 2
        $x_2_3 = "VP_PROMOTE_PIC" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Hiddapp_E_2147935649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hiddapp.E!MTB"
        threat_id = "2147935649"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hiddapp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "X/God/X/main" ascii //weight: 1
        $x_1_2 = "BANKSMS.txt" ascii //weight: 1
        $x_1_3 = "AkumaScreenShot.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

