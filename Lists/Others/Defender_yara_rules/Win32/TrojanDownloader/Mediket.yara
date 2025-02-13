rule TrojanDownloader_Win32_Mediket_2147574060_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mediket"
        threat_id = "2147574060"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mediket"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "]q1su30dpn" ascii //weight: 3
        $x_1_2 = "jfyqmp0f0fyf" ascii //weight: 1
        $x_1_3 = "d;]dpo0jh0tz`" ascii //weight: 1
        $x_1_4 = "]ntimq00fyf" ascii //weight: 1
        $x_3_5 = "iuuq;00xxx0xx030q1su00dpn0`0cfhjo00iq" ascii //weight: 3
        $x_1_6 = "[p0fNbq]E0nbjot]01su30d0n" ascii //weight: 1
        $x_1_7 = "]Epxom0beJogp0nbujpo" ascii //weight: 1
        $x_1_8 = "0t]Njd0ptpgu00oujTqz0bsf" ascii //weight: 1
        $x_2_9 = "ntunq00unm" ascii //weight: 2
        $x_4_10 = "Njds0tpgu]X0oepxt]0vssfou0fstjpo" ascii //weight: 4
        $x_1_11 = "0t]NdB0ff]NdB0ff0Wjs0ttdbo" ascii //weight: 1
        $x_3_12 = "]sfnnf0cbu" ascii //weight: 3
        $x_2_13 = "bcpvu;0mbol" ascii //weight: 2
        $x_2_14 = "PCK0DU0DMB0TJE" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

