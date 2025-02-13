rule TrojanSpy_Win64_Carfoban_A_2147716466_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Carfoban.A"
        threat_id = "2147716466"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Carfoban"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "marqueslimax01.info/prt3t0mw50/infx/" wide //weight: 4
        $x_2_2 = "/conta.php?chave=s3n4&url=" wide //weight: 2
        $x_4_3 = "200.98.201.231/listasw/pto/" wide //weight: 4
        $x_2_4 = "://carvascomercial.com/" wide //weight: 2
        $x_2_5 = "/atendimento81carvas.com/" wide //weight: 2
        $x_2_6 = "carvasltda.com/" wide //weight: 2
        $x_2_7 = "carvassa.com/" wide //weight: 2
        $x_2_8 = "carva32ssa.com/" wide //weight: 2
        $x_2_9 = "/k8wpo0/" wide //weight: 2
        $x_2_10 = {2f 00 6b 00 38 00 77 00 [0-2] 2e 00 68 00 74 00 6d 00 6c 00}  //weight: 2, accuracy: Low
        $x_2_11 = "k8wl=k8wg" wide //weight: 2
        $x_2_12 = "x.jpg" wide //weight: 2
        $x_1_13 = "k8wgh=" wide //weight: 1
        $x_1_14 = "b*b.c*om.b*r" wide //weight: 1
        $x_1_15 = "ban*cobra*sil" wide //weight: 1
        $x_1_16 = "sa*ntan*der" wide //weight: 1
        $x_1_17 = "bra*de*sco" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

