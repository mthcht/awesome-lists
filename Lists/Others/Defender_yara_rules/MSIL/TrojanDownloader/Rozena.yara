rule TrojanDownloader_MSIL_Rozena_DHE_2147913914_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Rozena.DHE!MTB"
        threat_id = "2147913914"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "BypassLoad.exe" ascii //weight: 5
        $x_1_2 = "https://jcxjg.fun/test/de_shellcode" wide //weight: 1
        $x_1_3 = "BypassLoad.pdb" ascii //weight: 1
        $x_1_4 = "BsijVUv2v+Ql/NM3pQv8uQ==" wide //weight: 1
        $x_1_5 = "AyD9Y9zW9dtvfqJzJb33gA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

