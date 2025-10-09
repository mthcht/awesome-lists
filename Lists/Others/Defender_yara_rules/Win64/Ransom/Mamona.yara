rule Ransom_Win64_Mamona_AMO_2147954655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Mamona.AMO!MTB"
        threat_id = "2147954655"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Mamona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encryption completed" ascii //weight: 1
        $x_2_2 = "YOUR FILES HAVE BEEN STOLEN AND ENCRYPTED" ascii //weight: 2
        $x_3_3 = "visit this tor link" ascii //weight: 3
        $x_4_4 = "vg6xwkmfyirv3l6qtqus7jykcuvgx6imegb73hqny2avxccnmqt5m2id.onion" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

