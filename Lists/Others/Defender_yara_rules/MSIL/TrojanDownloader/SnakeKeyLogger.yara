rule TrojanDownloader_MSIL_SnakeKeyLogger_RDD_2147842396_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/SnakeKeyLogger.RDD!MTB"
        threat_id = "2147842396"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "39b0de7d-1dce-4dab-93d1-b90a6c455072" ascii //weight: 1
        $x_1_2 = "Cnmpxbdinxn.Pwovyyombgthdglrhqbvf" wide //weight: 1
        $x_1_3 = "Stimntmwlmocdiaptoh" wide //weight: 1
        $x_1_4 = "//185.246.220.210/Ixchsp.bmp" wide //weight: 1
        $x_2_5 = {07 09 07 8e 69 5d 91 06 09 91 61 d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_SnakeKeyLogger_RDF_2147845146_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/SnakeKeyLogger.RDF!MTB"
        threat_id = "2147845146"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "9632ba35-5167-432f-a707-729c5794342a" ascii //weight: 1
        $x_1_2 = "//192.3.26.135/uo/Cuijo.dll" wide //weight: 1
        $x_1_3 = "Jtvkhmifsbmbmsnvxvwwlw.Ucmgaiftdzgdcsauxqcsl" wide //weight: 1
        $x_1_4 = "Odwalsitpbhqxuugmqfopjm" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_SnakeKeyLogger_RDE_2147896467_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/SnakeKeyLogger.RDE!MTB"
        threat_id = "2147896467"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8fb54868-7da8-47f6-adfc-af6bc57696b0" ascii //weight: 1
        $x_1_2 = "//185.246.220.210/Zlszypivld.bmp" wide //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "Get-Date" wide //weight: 1
        $x_1_5 = "Diiljtrjrpwstaeyokof.Kbejpnepglabvagfewcintl" wide //weight: 1
        $x_1_6 = "Mwnrenwqeonpfva" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_SnakeKeyLogger_RK_2147939356_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/SnakeKeyLogger.RK!MTB"
        threat_id = "2147939356"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://161.248.239.119/ADOLF/Penwcb.dat" wide //weight: 1
        $x_1_2 = "Lcdqv.exe" wide //weight: 1
        $x_1_3 = "yYBUA3LsPtLfx9UdR7.SGCU8x3RS0HdW3ntkH" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

