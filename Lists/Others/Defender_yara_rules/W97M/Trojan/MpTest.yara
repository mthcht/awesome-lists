rule Trojan_W97M_MpTest_A_2147645205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:W97M/MpTest.A"
        threat_id = "2147645205"
        type = "Trojan"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "MpTest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "a5d2bf868-2c3a-4088-9d3a-1040c4420ff0" ascii //weight: 1
        $x_1_2 = "0bcc6c17-7091-425f-adcc-991045fd8166" ascii //weight: 1
        $x_1_3 = "37d278e8-6ec3-4366-a0f8-c099b275d147" ascii //weight: 1
        $x_1_4 = "0baf0f92-347e-478b-bda0-16e87367ce27" ascii //weight: 1
        $x_1_5 = "a2588340-693b-4638-87dd-8d6f40322314" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

