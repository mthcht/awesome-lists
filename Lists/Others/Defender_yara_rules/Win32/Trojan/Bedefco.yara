rule Trojan_Win32_Bedefco_A_2147727222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bedefco.A"
        threat_id = "2147727222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bedefco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "127.0.0.1 update.eset.com" ascii //weight: 1
        $x_1_2 = "127.0.0.1 update10.lulusoft.com" ascii //weight: 1
        $x_2_3 = "/module/glamour" ascii //weight: 2
        $x_3_4 = "data28.somee.com/data32.zip" ascii //weight: 3
        $x_3_5 = "carma666.byethost12.com/32.html" ascii //weight: 3
        $x_3_6 = {57 69 6e 64 6f 77 73 20 44 72 69 76 65 72 20 53 65 72 76 69 63 65 00 [0-30] 00 5c 77 69 6e 69 6e 69 74 2e 65 78 65 00 [0-15] 20 2d 73 65 72 76 69 63 65 00 [0-60] 5c 73 79 73 74 65 6d 33 32 5c 78 62 6f 78 2d 73 65 72 76 69 63 65 2e 65 78 65 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

