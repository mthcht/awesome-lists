rule TrojanDownloader_Win32_Lerspeng_A_2147686490_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lerspeng.A"
        threat_id = "2147686490"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lerspeng"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {69 c0 01 01 01 01 57 8b 7d 08 c1 e9 02 f3 ab 8b ce 83 e1 03 f3 aa 5f}  //weight: 8, accuracy: High
        $n_8_2 = {4d 42 41 50 4f 32 33 32 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c}  //weight: -8, accuracy: High
        $x_4_3 = {83 f8 01 75 5b 39 7d fc 74 06 83 7d fc 06 75 50 8d 85 ?? ?? ff ff 50 ff 15}  //weight: 4, accuracy: Low
        $x_3_4 = {83 f8 01 74 0f 83 c6 04 81 fe d4 00 00 00 0f 82}  //weight: 3, accuracy: High
        $x_2_5 = "esoftmechanics.com/spengler/beatle" ascii //weight: 2
        $x_1_6 = "floormastersandiego.com/impugning/felsitic" ascii //weight: 1
        $x_1_7 = "217.199.161.78/mishapping/fleeceable" ascii //weight: 1
        $x_1_8 = "www.npbcgas.net/dyslexia/horizonless" ascii //weight: 1
        $x_1_9 = "alpha360.co.uk/mervin/number" ascii //weight: 1
        $x_1_10 = "passporttoplay.co.uk/duffer/salutations" ascii //weight: 1
        $x_1_11 = "202.164.41.251/goiters/wonderless" ascii //weight: 1
        $x_1_12 = "calumetcollection.com/adverb/songless" ascii //weight: 1
        $x_1_13 = ".luxuryboutiquehotelsandvillas.com/qualm/onder" ascii //weight: 1
        $x_1_14 = "wooden-flooring.org.uk/stern/just" ascii //weight: 1
        $x_1_15 = "evil.hn.vc/elastic/please" ascii //weight: 1
        $x_1_16 = "capital-auto-scrap.co.uk/scuzzier/doom" ascii //weight: 1
        $x_1_17 = "tresesenta.co/mores/wait" ascii //weight: 1
        $x_1_18 = "mbasistemas.com.ar/ennobles/moment" ascii //weight: 1
        $x_1_19 = "saespo.com/carped/loose" ascii //weight: 1
        $x_1_20 = "bclcarandcommercials.co.uk/transepts/your" ascii //weight: 1
        $x_1_21 = "skilifthofeck.de/gerardo/biggest" ascii //weight: 1
        $x_1_22 = "medosa.com.tr/pennons/fan" ascii //weight: 1
        $x_1_23 = "ftp.cbridges.org/cajoling/make" ascii //weight: 1
        $x_1_24 = "big5ops.co.za/willing/hill" ascii //weight: 1
        $x_1_25 = "arik-airlineuk.co.uk/habit/day" ascii //weight: 1
        $x_1_26 = "parroquialadivinamisericordia.com/starless/free" ascii //weight: 1
        $x_1_27 = "winthersachen.de/wriggly/moment" ascii //weight: 1
        $x_1_28 = "ftp.vipbalada.com/olduvai/just" ascii //weight: 1
        $x_1_29 = "ffgcorporate.com/clung/zero" ascii //weight: 1
        $x_1_30 = ".llantascasagrande.com/cussed/kill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((13 of ($x_1_*))) or
            ((1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_3_*) and 10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 9 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 5 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Lerspeng_B_2147686694_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lerspeng.B"
        threat_id = "2147686694"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lerspeng"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 73 73 00 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 57 ff 15 ?? ?? ?? ?? 83 f8 01 74 (0c|0f) 83 c6 04 (83 fe ??|81 fe ?? ?? ?? ??) 0f 82 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 45 fc 50 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 83 f8 01 75 ?? 39 7d fc 74 06 83 7d fc 06 75}  //weight: 1, accuracy: Low
        $x_1_4 = {69 c0 01 01 01 01 57 8b 7d 08 c1 e9 02 f3 ab 8b ce 83 e1 03 f3 aa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

