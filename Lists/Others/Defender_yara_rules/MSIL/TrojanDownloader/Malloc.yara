rule TrojanDownloader_MSIL_Malloc_GC_2147848000_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Malloc.GC!MTB"
        threat_id = "2147848000"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Malloc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Uxeizcc.exe" wide //weight: 1
        $x_1_2 = "http://80.66.75.37/Gfjtwbne.png" wide //weight: 1
        $x_1_3 = "Kjajgjvbiln.Bhjesncnyssy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

