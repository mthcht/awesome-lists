rule Trojan_AndroidOS_Anubis_A_2147797802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Anubis.A"
        threat_id = "2147797802"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Anubis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "visit_black_del" ascii //weight: 1
        $x_1_2 = "CpuFeature" ascii //weight: 1
        $x_1_3 = "Can't not finish recording" ascii //weight: 1
        $x_1_4 = "Connect clip files failed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Anubis_W_2147797959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Anubis.W"
        threat_id = "2147797959"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Anubis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {dc 05 02 03 44 06 04 05 e2 06 06 08 44 07 04 05 e0 07 07 18 b6 76 b0 16 b7 26 4b 06 04 05 e2 06 01 1d e0 01 01 03 b6 61 44 05 04 05 b7 51 d8 02 02 01 4b 01 03 02 28 e1}  //weight: 1, accuracy: High
        $x_1_2 = {12 08 e0 09 0b 10 b6 a9 4b 09 07 08 12 18 e0 09 0d 10 b6 c9 4b 09 07 08 44 [0-4] 07 [0-4] dc 07 02 04 e0 07 07 03 b9 [0-4] 8d [0-4] 48 07 [0-4] 03 b7 [0-4] 8d [0-4] 8d [0-4] 4f [0-4] 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Anubis_C_2147845598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Anubis.C"
        threat_id = "2147845598"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Anubis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/o1o/a1.php" ascii //weight: 2
        $x_2_2 = "fafdhassd.in" ascii //weight: 2
        $x_2_3 = "intervalLockInjTime" ascii //weight: 2
        $x_2_4 = "perehvat_sws" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

