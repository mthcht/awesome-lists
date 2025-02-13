rule Ransom_AndroidOS_LokiBot_A_2147782823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/LokiBot.A"
        threat_id = "2147782823"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "LokiBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/CriptActivity;" ascii //weight: 1
        $x_1_2 = "/Scrynlock;" ascii //weight: 1
        $x_1_3 = "/ForvardCall;" ascii //weight: 1
        $x_1_4 = "/InjectProcess;" ascii //weight: 1
        $x_1_5 = "/CommandService;" ascii //weight: 1
        $x_1_6 = "/CCLoker;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

