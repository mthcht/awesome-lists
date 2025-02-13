rule Trojan_Win32_Strakupa_A_2147697663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strakupa.A"
        threat_id = "2147697663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strakupa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "XunLei.XunLeiBHO" ascii //weight: 8
        $x_2_2 = ".cn/webhp?client=pub-1829095576409260" ascii //weight: 2
        $x_2_3 = ".com/webhp?client=pub-3776377769194153" ascii //weight: 2
        $x_1_4 = "s=3c33a767&w=55901&c=311&i=522&l=0&e=zw&t=http://www.x.com.cn" ascii //weight: 1
        $x_1_5 = "s=f2da95da&w=55901&c=255&i=150&l=0&e=zw&t=http://www.vancl.com" ascii //weight: 1
        $x_1_6 = "s=ed003385&w=55901&c=247&i=159&l=0&e=zw&t=http://www.dangdang.com" ascii //weight: 1
        $x_1_7 = "s=d402e475&w=55901&c=245&i=201&l=0&e=zw&t=http://www.amazon.cn" ascii //weight: 1
        $x_1_8 = "s=6be3ab6f&w=55901&c=228&i=143&l=0&e=zw&t=http://www.redmall.com.cn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

