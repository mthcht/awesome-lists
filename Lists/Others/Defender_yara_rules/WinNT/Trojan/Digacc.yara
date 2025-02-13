rule Trojan_WinNT_Digacc_A_2147629490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Digacc.gen!A"
        threat_id = "2147629490"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Digacc"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {bf 09 08 00 00 e8 07 25 00 00 3d 73 75 20 61 74 07 3d 61 72 20 65 75 05 bf 19 04 00 00}  //weight: 10, accuracy: High
        $x_1_2 = "Installer\\{ffffffff-F03B-4b40-A3D0-F62E04DD1C09}.exe" wide //weight: 1
        $x_1_3 = "\\device\\{60745EE5-D52E-482f-85C0-329310EE8D1C}" wide //weight: 1
        $x_1_4 = "/chcard?card_number=%I64u&card_cv_code" ascii //weight: 1
        $x_1_5 = "u.%02u.%u&mail=%s" ascii //weight: 1
        $x_1_6 = "Enum\\root\\LEGACY_x731" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

