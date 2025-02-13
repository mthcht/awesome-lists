rule Ransom_Win32_VB_Globster_2147724512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/VB.Globster"
        threat_id = "2147724512"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Reinkarnationer" ascii //weight: 2
        $x_2_2 = "Bygningsvaerker8" ascii //weight: 2
        $x_2_3 = "Curtails5" ascii //weight: 2
        $x_2_4 = "Fecklessness" ascii //weight: 2
        $x_2_5 = "Cabbaging" ascii //weight: 2
        $x_2_6 = "Udstdelsens" ascii //weight: 2
        $x_2_7 = "Eyeglasses3" ascii //weight: 2
        $x_2_8 = "Bathochrome5" ascii //weight: 2
        $x_2_9 = "Unplannedly" ascii //weight: 2
        $x_2_10 = "Versificeres4" ascii //weight: 2
        $x_2_11 = "Becassocked6" ascii //weight: 2
        $x_2_12 = "Vidtskuende0" ascii //weight: 2
        $x_2_13 = "Spisestuer" ascii //weight: 2
        $x_2_14 = "Pauseringerne" ascii //weight: 2
        $x_2_15 = "Summarization1" ascii //weight: 2
        $x_2_16 = "Aphotic5" ascii //weight: 2
        $x_2_17 = "Overcapitalisation" ascii //weight: 2
        $x_2_18 = "Beaconwise" ascii //weight: 2
        $x_2_19 = "Skillingstrykkenes8" ascii //weight: 2
        $x_2_20 = "Spiralbundens" ascii //weight: 2
        $x_2_21 = "Substantielle" ascii //weight: 2
        $x_2_22 = "Filmatiseringer" ascii //weight: 2
        $x_2_23 = "Frouziest" ascii //weight: 2
        $x_2_24 = "Supersuperior" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (15 of ($x*))
}

