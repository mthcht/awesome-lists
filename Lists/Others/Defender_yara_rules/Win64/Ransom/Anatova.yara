rule Ransom_Win64_Anatova_A_2147733266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Anatova.A"
        threat_id = "2147733266"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Anatova"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(d'qttfcjni'cbkbsb'tofchpt'(fkk'(vrnbs" wide //weight: 1
        $x_1_2 = "ka%pv%JK@%OUB%CLI@%JKI\\%hd}%755ng%qj%a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

