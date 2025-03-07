rule Ransom_Win64_Booran_PA_2147935365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Booran.PA!MTB"
        threat_id = "2147935365"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Booran"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HELLO_README.txt" ascii //weight: 1
        $x_1_2 = "!!! DANGER !!!" ascii //weight: 1
        $x_1_3 = "\\\\.\\pipe\\__rust_anonymous_pipe1__" ascii //weight: 1
        $x_1_4 = "Your files are encrypted, and currently unavailable." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

