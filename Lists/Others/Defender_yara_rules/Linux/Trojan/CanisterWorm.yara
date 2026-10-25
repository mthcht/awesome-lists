rule Trojan_Linux_CanisterWorm_SA_2147980927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CanisterWorm.SA"
        threat_id = "2147980927"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CanisterWorm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qL2ucqOZ_Yz79RHMPGNu/x3b7-E4DRuoxGX-flQf1/hckLU9-KAVh5ERguHtDy/3yeNYOsut9ta8si4zSK_" ascii //weight: 1
        $x_1_2 = "O6M-vPh6xeB-gT0hejkE/p9iRxgxre01Z6mlde3oL/L1oUrisWb5djEe-qaqub/lGM1OaXPhQCvU541K0e6" ascii //weight: 1
        $x_1_3 = "UiyG2lzzljgPe-pyVPmc/jrWgsAbANFLN8w0g9y-N/2Y6Xbmt5UgCIEL37IiWZ/g8qosq2y1CGEf_E9RgLT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

