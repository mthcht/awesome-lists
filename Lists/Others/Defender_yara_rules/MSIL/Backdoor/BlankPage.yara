rule Backdoor_MSIL_BlankPage_A_2147963060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/BlankPage.A!dha"
        threat_id = "2147963060"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlankPage"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Guid mismatch: expected {0} but actual is {1}" wide //weight: 1
        $x_1_2 = "expiration_time\":\"\\/Date(0+0000)" wide //weight: 1
        $x_1_3 = "Failed to receive data from file {0}: {1}" wide //weight: 1
        $x_1_4 = "{0}:/{1}:/children?$top={2}" wide //weight: 1
        $x_1_5 = "Failed to create upload session:" wide //weight: 1
        $x_1_6 = "Found {0} output(s) to send" wide //weight: 1
        $x_1_7 = "Sleeping for {0} in {1} mode..." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

