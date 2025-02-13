rule Backdoor_MSIL_Hulpob_A_2147686237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Hulpob.A"
        threat_id = "2147686237"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hulpob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "|Botkiller executed" wide //weight: 1
        $x_1_2 = "|Shellcode executed" wide //weight: 1
        $x_1_3 = "|File Downloaded And Executed" wide //weight: 1
        $x_1_4 = {1f 1d 0f 01 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
        $x_1_5 = {1f 1d 0f 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

