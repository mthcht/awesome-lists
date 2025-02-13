rule Worm_Win32_Civonxres_A_2147706940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Civonxres.A"
        threat_id = "2147706940"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Civonxres"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "/XQDBHO5.exe" ascii //weight: 4
        $x_2_2 = "w.99999999999.com.cn/SCVH0ST.EXE" ascii //weight: 2
        $x_2_3 = "999.com.cn/SERVICS.EXE" ascii //weight: 2
        $x_2_4 = "A692062A-4782-461B-BE98-B520F01F96FC" ascii //weight: 2
        $x_1_5 = "/www.99999999999.com.cn/" ascii //weight: 1
        $x_1_6 = "UmFyIRoHAM+QcwAADQAAAAAAAAAjrHQgkj4AggMAAP0JAAAC" ascii //weight: 1
        $x_1_7 = "A03ABfghcnEfudadsfdgtertgsdsAdfgdfSDFdfgDGFdewrT" ascii //weight: 1
        $x_1_8 = "4lk5lk435kl435kl4j5l43j5l4k5l43k5l3kl3545kl4ejhg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

