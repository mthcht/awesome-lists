rule Trojan_Win64_Floomyeda_C_2147731239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Floomyeda.C"
        threat_id = "2147731239"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Floomyeda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "2015-04-18T" wide //weight: 10
        $x_10_2 = "T$TiBzxV@22" ascii //weight: 10
        $x_10_3 = "T$TiCwxV@12Tr22253" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Floomyeda_D_2147731240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Floomyeda.D"
        threat_id = "2147731240"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Floomyeda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {49 6e 73 74 61 6c 6c 53 65 72 76 69 63 65 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 100, accuracy: High
        $x_10_2 = "wcnbis_x64.dll" ascii //weight: 10
        $x_10_3 = "wcnbis_x86.dll" ascii //weight: 10
        $x_10_4 = "wcnbis_x32.dll" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

