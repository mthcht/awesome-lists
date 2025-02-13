rule TrojanProxy_MSIL_Mictanort_A_2147696834_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:MSIL/Mictanort.A"
        threat_id = "2147696834"
        type = "TrojanProxy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mictanort"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NNYYrr.Resources.makecert.exe" ascii //weight: 1
        $x_1_2 = "Fiddler.frmPrompt.resources" ascii //weight: 1
        $x_1_3 = "Tamir.SharpSsh.jsch.examples.InputForm.resources" ascii //weight: 1
        $x_1_4 = {09 4d 69 63 72 6f 20 4e 65 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

