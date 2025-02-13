rule TrojanDownloader_MSIL_Vomsaload_A_2147696017_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Vomsaload.A"
        threat_id = "2147696017"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vomsaload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2kSMuoGXMravhy1MWys9TaPHbMkE7FtYPKxY/g3TnZ4=" wide //weight: 1
        $x_1_2 = "QCSag7geDpDaBOFt5DgiRGjL/ZlNqUTkmSNo+KjiGD0=" wide //weight: 1
        $x_1_3 = "6ygdIhZ9kkOiqtV3otfnmQ==" wide //weight: 1
        $x_1_4 = "tVNnwTkbnfhziC364YUG6bgyZbbkzobvPMkbDYCRLpk=" wide //weight: 1
        $x_1_5 = "8rKoGXkRG3M88Up/LUywOOX9gGzLhIsSc5ywAFIFc+T9ybdFz66+st9e6OvWcfq5" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

