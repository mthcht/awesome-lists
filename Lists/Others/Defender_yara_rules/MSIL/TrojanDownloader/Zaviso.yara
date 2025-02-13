rule TrojanDownloader_MSIL_Zaviso_A_2147696359_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Zaviso.A"
        threat_id = "2147696359"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zaviso"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "180Q5nKj6mTU1ZB3FMDO1AKsjVYKYSQXR2m2ZMB9DsRLDy5Dga/CkQodQxkfYStHmaBSkOCDHgL" wide //weight: 1
        $x_1_2 = "KQ8UK+Wx9NAPgURtLCQEhXZzArYc06dt7uTB4V49S3QfqxJTEHAv5g==" wide //weight: 1
        $x_1_3 = "YaMgkGCuKvfP1ZkQPhpzUA==" wide //weight: 1
        $x_1_4 = "gizacpK3RBY=" wide //weight: 1
        $x_1_5 = "rthUNYCL6ds=" wide //weight: 1
        $x_1_6 = "BkR6w8XpPpttGDfEbeRvsg==" wide //weight: 1
        $x_1_7 = "aUYIXrwi6vs=" wide //weight: 1
        $x_1_8 = "IgzofiO4pg0=" wide //weight: 1
        $x_1_9 = "LWdpbgS8kTvBPI7Bt9USJ+bEPZjeY6uW8aDDdSj8wuGcAAFaQEZHtkvC8OnutjZ1YsmORiO7J35" wide //weight: 1
        $x_1_10 = "q/np0w8l8to=" wide //weight: 1
        $x_1_11 = "DC9JqbSthbM=" wide //weight: 1
        $x_1_12 = "v3Xsn7kVmOA=" wide //weight: 1
        $x_1_13 = "R2bFe1VoaBLP1ZkQPhpzUA==" wide //weight: 1
        $x_1_14 = "+nV/oqIbrQp3/ajCV/Hhwg==" wide //weight: 1
        $x_1_15 = "TOD09H/SFSsPMtYSYP8JGNFEZVFLUFnpCZmLxGCSxcquDMg6RDODJEdXFS/7FL+RjezpOLLltrE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

