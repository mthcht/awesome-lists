rule Trojan_AndroidOS_Booger_A_2147789005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Booger.A"
        threat_id = "2147789005"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Booger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[anzhuo_test]" ascii //weight: 1
        $x_1_2 = "Lcn/com/xiaol/livewallpaper/jpqcmn/" ascii //weight: 1
        $x_1_3 = "com.mt.airad.MultiAD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

