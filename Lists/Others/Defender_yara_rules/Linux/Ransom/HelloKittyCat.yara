rule Ransom_Linux_HelloKittyCat_A1_2147908285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/HelloKittyCat.A1"
        threat_id = "2147908285"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "HelloKittyCat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sunshine/movement" ascii //weight: 1
        $x_1_2 = "StartEnc" ascii //weight: 1
        $x_1_3 = "encrypter" ascii //weight: 1
        $x_1_4 = "brute" ascii //weight: 1
        $x_1_5 = "SSH." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_HelloKittyCat_A3_2147908286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/HelloKittyCat.A3"
        threat_id = "2147908286"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "HelloKittyCat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "start_enc" ascii //weight: 1
        $x_1_2 = "enc_done" ascii //weight: 1
        $x_2_3 = "ITSSHOWKEY" ascii //weight: 2
        $x_2_4 = "prepare ITSBTC btc" ascii //weight: 2
        $x_2_5 = "contact email:ITSEMAIL" ascii //weight: 2
        $x_2_6 = "GGGITSSHOWKEY00" ascii //weight: 2
        $x_3_7 = "service@hellokittycat.online" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

