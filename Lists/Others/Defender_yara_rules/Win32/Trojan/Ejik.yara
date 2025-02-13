rule Trojan_Win32_Ejik_B_2147606755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ejik.B"
        threat_id = "2147606755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ejik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb f0 5f 5e 5b 59 5d c3 00 00 ff ff ff ff 04 00 00 00 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {45 58 45 46 49 4c 45 00 ff ff ff ff 10 00 00 00 52 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 04 00 03 00 00}  //weight: 1, accuracy: Low
        $x_2_3 = {45 58 45 46 49 4c 45 00 ff ff ff ff 04 00 03 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 10 00 2e 64 6c 6c 00 [0-4] ff ff ff ff 10 00 00 00 52 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 20}  //weight: 2, accuracy: Low
        $x_5_4 = {eb eb 5e 5b 59 59 5d c3 [0-4] ff ff ff ff ?? 00 00 00 10 00 2e 69 6e 69 00 [0-4] ff ff ff ff 02 00 00 00 49 44 00 [0-4] ff ff ff ff 08 00 00 00 73 65 74 74 69 6e 67 73 00 [0-4] (55|53)}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ejik_C_2147606756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ejik.C"
        threat_id = "2147606756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ejik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TIdCookieManager" ascii //weight: 1
        $x_1_2 = "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP" ascii //weight: 1
        $x_1_3 = {45 58 45 46 49 4c 45 [0-4] ff ff ff ff 15 00 00 00 73 65 74 75 70 6f 6c 5f 04 00 5f 04 00 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 63 6e 2f 64 61 74 61 5f 61 64 64 2e 61 73 70 78 3f 66 69 6c 65 6e 61 6d 65 3d 73 65 74 75 70 6f 6c 5f 04 00 5f 04 00 2e 65 78 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ejik_A_2147607436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ejik.gen!A"
        threat_id = "2147607436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ejik"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_1_2 = {eb f0 5f 5e 5b 59 5d c3 00 00 ff ff ff ff 04 00 00 00 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 58 45 46 49 4c 45 00 ff ff ff ff 10 00 00 00 52 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 0c 00 ff ff ff ff 03 00 00 00 ?? (61|2d|7a|30|2d|39) (61|2d|7a|30|2d|39) 00}  //weight: 1, accuracy: Low
        $x_1_4 = "setupday" ascii //weight: 1
        $x_1_5 = "e-jok.cn/cnfg" ascii //weight: 1
        $x_1_6 = {62 69 7a 36 37 38 2e 63 6e 2f 53 (4b 6c 69|65 61 72 63 68 49 6d 61) 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_7 = "resiifers.ini" ascii //weight: 1
        $x_1_8 = "windownewsups.ini" ascii //weight: 1
        $x_1_9 = {70 61 73 73 77 6f 72 64 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 73 65 72 6e 61 6d 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 61 73 73 77 6f 72 64 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 73 65 72 6e 61 6d 65}  //weight: 1, accuracy: Low
        $x_1_10 = "EIdInvalidServiceName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

