rule TrojanSpy_MSIL_Nitwil_A_2147696205_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Nitwil.A"
        threat_id = "2147696205"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nitwil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Knight Logger Started..." wide //weight: 2
        $x_2_2 = "[LOGS]Knight Logger of {0} - {1}" wide //weight: 2
        $x_2_3 = "Knight Logger sent logs of {0} - {1}" wide //weight: 2
        $x_2_4 = "[ACCOUNTS]Knight Logger of {0} - {1}" wide //weight: 2
        $x_2_5 = "[FIRST RUN]Knight Logger first run on {0} - {1}" wide //weight: 2
        $x_2_6 = "[WALLETS]Knight Logger of {0} - {1}" wide //weight: 2
        $x_1_7 = "keylog_{0}{1}" wide //weight: 1
        $x_1_8 = "Started Uploading Logs..." wide //weight: 1
        $x_1_9 = "Wallets Uploaded Successfully" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

