rule Trojan_Win32_Pususcret_A_2147710920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pususcret.A"
        threat_id = "2147710920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pususcret"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CLQ]]]]]]kq{#*6AOWberw$-99:IPZ^f" ascii //weight: 2
        $x_2_2 = "GSWdddddp!'4<JXgr|',5=EMN[`ijmoz" ascii //weight: 2
        $x_1_3 = "L[]kkkkkn|+5=BJOQ\\\\\\fffkmu#11255" ascii //weight: 1
        $x_1_4 = "DPQYYYYYhjy|*1:HKZdhtx\"'6<GP]^`g" ascii //weight: 1
        $x_1_5 = "MQWaaaaaeoz(5DEJYgloz&(5=HLLX^mo" ascii //weight: 1
        $x_1_6 = "KNOUUUUUUWdkru})7:CRT]lls#1=BOPQ" ascii //weight: 1
        $x_1_7 = "FGKVVVVV]jqtvz$(2>GLWdhikww%+:FL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

