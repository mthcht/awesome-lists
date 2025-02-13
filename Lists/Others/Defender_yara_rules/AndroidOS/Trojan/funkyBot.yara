rule Trojan_AndroidOS_funkyBot_A_2147744225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/funkyBot.A"
        threat_id = "2147744225"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "funkyBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "d35f86c667b275ca1d3066d3fac4587d" ascii //weight: 2
        $x_2_2 = "432103a51751cff2a591a9abf9499c0f" ascii //weight: 2
        $x_1_3 = "Ljava/util/zip/ZipFile" ascii //weight: 1
        $x_1_4 = "aGVsbG8gd29ybGQgbXkzMg==" ascii //weight: 1
        $x_1_5 = "csn-resp.data" ascii //weight: 1
        $x_1_6 = "libcsn2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_funkyBot_B_2147744226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/funkyBot.B"
        threat_id = "2147744226"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "funkyBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "in findDex start" ascii //weight: 1
        $x_1_2 = "csn_" ascii //weight: 1
        $x_1_3 = "app_csn0/.unzip/oat" ascii //weight: 1
        $x_1_4 = ".csn.dex" ascii //weight: 1
        $x_1_5 = ".unzip/d-classes.dex" ascii //weight: 1
        $x_1_6 = "com/security/shell/JNITools" ascii //weight: 1
        $x_2_7 = {80 b5 6f 46 8a b0 13 46 8c 46 86 46 09 90 08 91 07 92 08 98 02 93 cd f8 04 c0 cd f8 00 e0 ff f7 12 e8 06 90 51 20 07 f8 11 0c 08 98 40 08 04 90 04 98 08 99 88 42 03 d9 ff e7 08 98 04 90 ff e7 00 20 03 90 ff e7 03 98 08 99 88 42 19 d2 ff e7 03 98 04 99 88 42 09 d2 ff e7 09 98 03 99 40 5c 17 f8 11 2c 50 40 06 9a 50 54 05 e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

