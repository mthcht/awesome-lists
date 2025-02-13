rule Backdoor_PowerShell_Shaningning_H_2147711346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:PowerShell/Shaningning.H"
        threat_id = "2147711346"
        type = "Backdoor"
        platform = "PowerShell: "
        family = "Shaningning"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \"powershell -C \"\"$data = [System.Convert]::FromBase64String('" ascii //weight: 1
        $x_1_2 = "System.IO.MemoryStream;$ms.Write($data,0,$data.Length);$ms.Seek(0,0)" ascii //weight: 1
        $x_1_3 = "System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

